"""Engine settings, read from the process environment. Entry points opt into `.env`.

`load_env()` is NOT called at import time, and must not be. Importing any `vectasec.*` module has
to be free of environmental side effects, because this package is not only imported by its own
entry points: the collector imports `vectasec.scan` for `fingerprint()` (collector/main.py), and
it then reads its ENTIRE security posture — control-plane URL, TLS verification, target
credentials — out of `os.environ`. An import that folded an on-disk `.env` into `os.environ`
would let a file nobody audits fill in whatever the operator left unset, and
`VECTASEC_VERIFY_TLS` is normally unset. A `.env` reachable from the collector's cwd could
therefore silently turn off certificate verification on the one connection that carries the
tenant service token, and none of it would show in `docker inspect` or `kubectl describe pod`.
So: only `cli.main()` and `api.main.main()` call `load_env()`, and importing a pure function
gets nothing.

`Settings` reads `os.environ` on every access rather than binding at class-body evaluation. That
is what makes the split above work at all: an entry point that imports this module (directly or
through `.db`, `.scan`, `.ai`) and calls `load_env()` afterwards must still see the loaded
values, which a value bound at import time could never do.
"""
import os
import re
import pathlib

DEMO_TENANT = "00000000-0000-0000-0000-000000000001"


def load_env() -> None:
    """Fold the nearest `.env` at or above cwd into os.environ. Entry points only.

    Existing environment variables always win — this only fills in what is unset.
    """
    start = pathlib.Path.cwd()
    for d in [start, *start.parents]:
        f = d / ".env"
        if f.exists():
            for line in f.read_text().splitlines():
                m = re.match(r"^([A-Z_]+)=(.*)$", line)
                if m and m.group(1) not in os.environ:
                    os.environ[m.group(1)] = m.group(2)
            return


class Settings:
    demo_tenant: str = DEMO_TENANT

    @property
    def database_url(self) -> str:
        return os.environ.get("DATABASE_URL", "")

    @property
    def kafka_bootstrap(self) -> str:
        return os.environ.get("KAFKA_BOOTSTRAP", "localhost:9092")

    @property
    def anthropic_api_key(self) -> str:
        # Optional: unset means the grounded-AI layer runs its deterministic fallback.
        return os.environ.get("ANTHROPIC_API_KEY", "").strip()

    @property
    def engine_port(self) -> int:
        return int(os.environ.get("ENGINE_PORT", "8000") or 8000)


settings = Settings()
