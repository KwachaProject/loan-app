#!/usr/bin/env bash
set -euo pipefail

export FLASK_ENV=production
echo "🚀  Starting deployment script…"

###############################################################################
# 0. Sanity‑check required secrets
###############################################################################
if [[ -z "${ADMIN_EMAIL:-}" || -z "${ADMIN_PASSWORD:-}" ]]; then
  echo "❌  ADMIN_EMAIL and ADMIN_PASSWORD must be set" >&2
  exit 1
fi

###############################################################################
# 1. Ensure critical columns exist (runs every deploy — safe & idempotent)
###############################################################################
echo "🆘  Ensuring critical columns exist…"

python - <<'PY'
from sqlalchemy import create_engine, inspect, text
import os, sys

url = os.environ["DATABASE_URL"]
if url.startswith("postgres://"):
    url = url.replace("postgres://", "postgresql://", 1)

engine = create_engine(url, isolation_level="AUTOCOMMIT")

NEEDED = {
    "current_balance"     : "NUMERIC(12,2) DEFAULT 0.0",
    "top_up_balance"      : "NUMERIC(12,2) DEFAULT 0.0",
    "settlement_balance"  : "NUMERIC(12,2) DEFAULT 0.0",
    "settlement_type"     : "VARCHAR(50)",
    "settling_institution": "VARCHAR(255)",
    "settlement_reason"   : "TEXT",
    "parent_loan_id"      : "INTEGER",
}

with engine.connect() as conn:
    cols = {c["name"] for c in inspect(conn).get_columns("loan_applications")}
    for col, ddl in NEEDED.items():
        if col in cols:
            print(f" ✅ {col} ok")
            continue
        try:
            conn.execute(text(f"ALTER TABLE loan_applications ADD COLUMN {col} {ddl}"))
            print(f" ➕ added {col}")
        except Exception as e:
            print(f" ⚠️  could not add {col}: {e}")

print("✅  Column check complete")
PY

###############################################################################
# 2. Reconcile Alembic version with repo; decide if upgrade is needed
###############################################################################
echo "🗄️  Reconciling Alembic version…"

NEEDS_UPGRADE=$(python - <<'PY'
import os, sys, subprocess
from sqlalchemy import create_engine, text

url = os.environ["DATABASE_URL"].replace("postgres://", "postgresql://", 1)
engine = create_engine(url, isolation_level="AUTOCOMMIT")

# repo head
head = subprocess.check_output(["alembic", "heads", "-s"]).decode().split()[0]

with engine.connect() as conn:
    conn.execute(text("CREATE TABLE IF NOT EXISTS alembic_version (version_num VARCHAR(32) NOT NULL)"))
    current = conn.execute(text("SELECT version_num FROM alembic_version")).scalar()

if current == head:
    print("✅  DB already at repo head:", head)
    sys.exit(0)          # everything in sync
else:
    print("🟡  DB revision:", current, "→ repo head:", head)
    # fast‑forward the version table so that upgrade can apply diffs only
    with engine.connect() as conn:
        conn.execute(text("DELETE FROM alembic_version"))
        conn.execute(text("INSERT INTO alembic_version (version_num) VALUES (:rev)"), {"rev": current or head})
    sys.exit(99)         # signal caller that upgrade should run
PY
echo $?)                 # capture exit status
# shell variable now contains 0 or 99

###############################################################################
# 3. Apply migrations only if requested (code 99)
###############################################################################
if [[ "$NEEDS_UPGRADE" -eq 99 ]]; then
  echo "⏫  Running flask db upgrade…"
  flask db upgrade
  echo "✅  Alembic upgrade complete"
fi

###############################################################################
# 4. Seed roles / permissions
###############################################################################
echo "👥  Seeding roles / permissions…"
python - <<'PY'
from app import app, initialize_roles_permissions
with app.app_context():
    initialize_roles_permissions()
    print("✅  RBAC initialised")
PY

###############################################################################
# 5. Ensure admin user exists
###############################################################################
echo "👑  Ensuring admin account…"
python - <<'PY'
from app import app, db, User
from werkzeug.security import generate_password_hash
import os, time

email    = os.environ["ADMIN_EMAIL"]
password = os.environ["ADMIN_PASSWORD"]

with app.app_context():
    admin = User.query.filter_by(email=email).first()
    if admin:
        print("✅  Admin already present")
    else:
        username = "admin"
        if User.query.filter_by(username=username).first():
            username = f"admin_{int(time.time())}"
        admin = User(username=username,
                     email=email,
                     password_hash=generate_password_hash(password))
        db.session.add(admin)
        db.session.commit()
        print(f"✅  Created admin user {email} ({username})")
PY

###############################################################################
# 6. Launch Gunicorn
###############################################################################
echo "🚀  Launching Gunicorn…"
exec gunicorn --workers 4 --bind 0.0.0.0:${PORT:-8000} app:app
