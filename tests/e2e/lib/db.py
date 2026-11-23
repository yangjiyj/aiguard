import psycopg
import os

DSN = os.getenv(
    "E2E_DB_DSN",
    "postgresql://newapi:newapi@127.0.0.1:15432/newapi",
)


def conn():
    return psycopg.connect(DSN, autocommit=True)
