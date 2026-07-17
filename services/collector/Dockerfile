# VectaSec collector.
#
# Build context is services/, not services/collector/, because the image installs the engine from
# a sibling path — the collector reuses the engine's connectors and detectors rather than forking
# them:
#
#   docker build -f services/collector/Dockerfile -t vectasec/collector:0.0.1 services/
#
# The image runs one process that only ever dials out. It EXPOSEs nothing, on purpose.

FROM python:3.12-slim AS build

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PATH=/opt/venv/bin:$PATH

RUN python -m venv /opt/venv

COPY engine    /src/engine
COPY collector /src/collector
# Installed, not mounted: the shipped image must not be able to pick up a connector from a
# writable volume at runtime.
RUN pip install /src/engine /src/collector


FROM python:3.12-slim AS runtime

COPY --from=build /opt/venv /opt/venv

ENV PATH=/opt/venv/bin:$PATH \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    VECTASEC_TARGETS_FILE=/etc/vectasec/targets.json \
    VECTASEC_STATE_DIR=/var/lib/vectasec

# Everything in one layer, ending by deleting the tooling that made the layer possible. After
# this there is no shell, no package manager and no pip in the image: `docker exec … sh` fails,
# and so does anything that lands RCE here and reaches for a shell. The cost is honest — you
# cannot debug this container interactively; use `preview`/`check` and the logs.
RUN set -eux; \
    useradd --uid 10001 --user-group --no-create-home --shell /usr/sbin/nologin collector; \
    mkdir -p /var/lib/vectasec /etc/vectasec; \
    chown 10001:10001 /var/lib/vectasec; \
    chmod 0700 /var/lib/vectasec; \
    rm -rf /var/lib/apt/lists/* /usr/local/lib/python3.12/ensurepip; \
    rm -f  /usr/local/bin/pip /usr/local/bin/pip3 /usr/local/bin/pip3.12; \
    rm -rf /usr/bin/apt* /usr/bin/dpkg* /usr/bin/gpg* /sbin/apt*; \
    rm -f  /bin/sh /bin/bash /bin/dash /usr/bin/env

# The state dir holds sha256(enrollment token) and a collector id — never a usable credential.
VOLUME ["/var/lib/vectasec"]

USER 10001:10001
STOPSIGNAL SIGTERM

# Exec form: no shell is involved, which is what lets the shell be deleted above.
ENTRYPOINT ["/opt/venv/bin/vectasec-collector"]
CMD ["run"]
