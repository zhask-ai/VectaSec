"""_SecretFilter — the scrub on the way to the customer's log shipper.

The shipper leaves the customer's network even though the collector does not, so a credential in
a log line is an exfiltration path. The filter's own docstring names the case it exists for: "a
connector's exception text can carry a URL with userinfo in it". These tests pin that case, and
it is not the obvious one — an exception passed as a `%s` arg is an OBJECT, and logging
stringifies it *after* every filter has run.
"""
import logging

import pytest

from collector.main import _SecretFilter

PW = "R4bb1tPassLong"
SECRETS = {PW}


@pytest.fixture
def emitted(caplog):
    """Returns a function that runs one log call through the real filter and hands back the text
    a handler would actually write — formatted, which is the only thing that leaves."""
    def run(fn):
        logger = logging.getLogger("test_secret_filter")
        logger.setLevel(logging.DEBUG)
        logger.propagate = False
        handler = logging.StreamHandler()
        records: list = []
        handler.emit = records.append          # capture post-filter records
        handler.addFilter(_SecretFilter(SECRETS))
        logger.handlers = [handler]
        try:
            fn(logger)
        finally:
            logger.handlers = []
        fmt = logging.Formatter("%(message)s")
        return "\n".join(fmt.format(r) for r in records)
    return run


def test_an_exception_object_arg_is_scrubbed(emitted):
    """THE regression. main.py's cycle-failure line passes the exception object, not str(e).
    The old filter only redacted args that were `isinstance(a, str)`, so this went out whole."""
    e = RuntimeError(f"auth failed for user svc with password {PW}")
    out = emitted(lambda log: log.warning("cycle failed: %s: %s (retry in ~%.0fs)",
                                          type(e).__name__, e, 4.0))
    assert PW not in out
    assert "cycle failed: RuntimeError: auth failed" in out
    assert "[redacted]" in out
    assert "retry in ~4s" in out          # the message still formats correctly


def test_a_traceback_is_scrubbed(emitted):
    """exc_info was a total blind spot: the filter never touched it, and a traceback carries the
    argument values of every frame."""
    try:
        raise RuntimeError(f"connecting to amqp://svc:{PW}@rabbit.internal")
    except RuntimeError:
        out = emitted(lambda log: log.warning("boom", exc_info=True))
    assert PW not in out
    assert "RuntimeError" in out


def test_a_secret_in_the_message_itself_is_still_scrubbed(emitted):
    out = emitted(lambda log: log.info("using %s", PW))
    assert PW not in out and "[redacted]" in out


def test_url_userinfo_is_scrubbed_even_when_the_secret_is_not_one_we_hold(emitted):
    """The shape layer. A connector can read a credential off the target that we never held, so
    value-scrubbing alone would miss it."""
    e = RuntimeError("connection refused for amqp://admin:notoursecret@rabbit.internal")
    out = emitted(lambda log: log.warning("job failed: %s", e))
    assert "notoursecret" not in out and "[redacted]@rabbit.internal" in out


def test_non_string_args_still_format(emitted):
    """The scrub must not corrupt ordinary logging — this is main.py's push line."""
    out = emitted(lambda log: log.info("job %s: pushed %s findings over %s resources in %sms",
                                       "j-1", 3, 12, 450))
    assert out == "job j-1: pushed 3 findings over 12 resources in 450ms"


def test_percent_style_dict_args_do_not_blow_up(emitted):
    """Latent before the fix: `tuple(record.args)` on a dict yields a tuple of KEYS, and the
    handler then dies with 'format requires a mapping' — a log call that raises inside the
    collector's own error path."""
    out = emitted(lambda log: log.info("target %(name)s failed", {"name": "prod-kafka"}))
    assert out == "target prod-kafka failed"


def test_a_literal_percent_survives_the_rewrite(emitted):
    """The filter interpolates and clears args; a redacted message containing % must not be
    re-interpolated by logging afterwards."""
    out = emitted(lambda log: log.info("progress: %s", "50% done"))
    assert out == "progress: 50% done"
