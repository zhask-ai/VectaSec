import psycopg

from .config import settings


def connect() -> psycopg.Connection:
    if not settings.database_url:
        raise SystemExit("DATABASE_URL is not set (check .env)")
    return psycopg.connect(settings.database_url, connect_timeout=15)
