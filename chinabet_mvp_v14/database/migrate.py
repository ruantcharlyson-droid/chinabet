import os
from sqlalchemy import create_engine,text
from pathlib import Path
url=os.getenv("DATABASE_URL","postgresql+psycopg2://chinabet:chinabet@db:5432/chinabet")
e=create_engine(url)
base=Path(__file__).parent/"migrations"
with e.begin() as c:
    c.execute(text("CREATE TABLE IF NOT EXISTS schema_migrations(version VARCHAR(32) PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW())"))
    for p in sorted(base.glob("*.sql")):
        for stmt in p.read_text().split(";"):
            if stmt.strip(): c.execute(text(stmt))
print("migrations ok")
