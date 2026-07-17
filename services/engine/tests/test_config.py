"""Importing the engine must not touch os.environ.

This is a boundary test, not a style test. The collector imports `vectasec.scan` for
`fingerprint()` and then reads its whole security posture — control-plane URL, TLS verification,
target credentials — out of `os.environ`. If importing the engine folded an on-disk `.env` into
the environment, a file nobody audits could fill in anything the operator left unset, and
`VECTASEC_VERIFY_TLS` is normally unset. That is certificate verification silently off on the
connection that carries the tenant service token.

Run in a subprocess with a clean environment and a planted `.env`, because the only honest way to
test an import-time side effect is a fresh interpreter.
"""
import json
import os
import subprocess
import sys
import textwrap

import pytest

DOTENV = textwrap.dedent("""\
    VECTASEC_VERIFY_TLS=false
    VECTASEC_CONTROL_PLANE_URL=http://cp.attacker.example
    DATABASE_URL=postgres://planted/db
    """)

PROBE = textwrap.dedent("""\
    import json, os, sys
    import vectasec.scan            # the collector's import, for fingerprint()
    print(json.dumps({k: os.environ.get(k) for k in
                      ("VECTASEC_VERIFY_TLS", "VECTASEC_CONTROL_PLANE_URL", "DATABASE_URL")}))
    """)


def _run(code: str, cwd, env=None) -> str:
    env = {"PATH": os.environ.get("PATH", ""), "PYTHONPATH": os.pathsep.join(sys.path), **(env or {})}
    r = subprocess.run([sys.executable, "-c", code], cwd=str(cwd), env=env,
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    return r.stdout.strip().splitlines()[-1]


@pytest.fixture
def planted(tmp_path):
    (tmp_path / ".env").write_text(DOTENV)
    work = tmp_path / "work"
    work.mkdir()
    return work        # cwd is BELOW the .env — _load_env walked upward, which is the reach


def test_importing_the_engine_does_not_inject_a_dotenv_into_the_environment(planted):
    """The regression: `import vectasec.scan` used to run _load_env() at module scope."""
    seen = json.loads(_run(PROBE, planted))
    assert seen == {"VECTASEC_VERIFY_TLS": None,
                    "VECTASEC_CONTROL_PLANE_URL": None,
                    "DATABASE_URL": None}


def test_an_entry_point_still_gets_the_dotenv(planted):
    """The other half: `vectasec` the CLI is supposed to read .env. Losing that would trade a
    config-injection channel for an engine that cannot find its database."""
    out = _run(textwrap.dedent("""\
        from vectasec.config import load_env, settings
        assert settings.database_url == "", "settings bound at import — load_env() would be dead"
        load_env()
        print(settings.database_url)
        """), planted)
    assert out == "postgres://planted/db"


def test_the_real_environment_still_beats_the_dotenv(planted):
    out = _run(textwrap.dedent("""\
        from vectasec.config import load_env, settings
        load_env()
        print(settings.database_url)
        """), planted, env={"DATABASE_URL": "postgres://operator/db"})
    assert out == "postgres://operator/db"
