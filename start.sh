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
# 1.  Make sure the critical columns exist  (works on Render free tier)
#     Runs every deploy; if the column is already there Postgres skips it.
###############################################################################
echo "🆘  Ensuring critical columns exist in loan_applications…"

python - <<'PY'
from sqlalchemy import create_engine, inspect, text
import os

# Convert old-style URL if needed
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
            print(f"✅  {col} already present")
            continue
        print(f"➕  adding {col}")
        try:
            conn.execute(text(f"ALTER TABLE loan_applications "
                              f"ADD COLUMN {col} {ddl}"))
            print("   → done")
        except Exception as e:
            # Don’t crash the deploy; just warn
            print(f"   ⚠️  could not add {col}: {e}")
PY

echo "✅  Column check complete"

###############################################################################
# 2. Robust Alembic migration handling (recovers from lost revision)
###############################################################################
echo "🗄️  Applying database migrations…"

if flask db upgrade; then
  echo "✅  Alembic upgraded cleanly"
else
  echo "⚠️  Alembic upgrade failed – starting recovery"
  
  # Get the actual head revision from the repo
  HEAD_REV="$(alembic heads | awk 'NR==1{print $1}')"
  echo "🔎  Repo head revision is ${HEAD_REV}"

  # Force‑stamp DB with that revision
  python - <<PY
import os, sys
from sqlalchemy import create_engine, text

db_url = os.environ["DATABASE_URL"].replace("postgres://", "postgresql://", 1)
engine  = create_engine(db_url, isolation_level="AUTOCOMMIT")

with engine.connect() as conn:
    conn.execute(text("""
        CREATE TABLE IF NOT EXISTS alembic_version (
            version_num VARCHAR(32) NOT NULL
        )
    """))
    conn.execute(text("DELETE FROM alembic_version"))
    conn.execute(text("INSERT INTO alembic_version (version_num) VALUES (:rev)"),
                 {"rev": "${HEAD_REV}"})
    print(f"✅  Force‑stamped alembic_version with ${HEAD_REV}")
PY

  # Retry the upgrade one more time; if it still fails we abort
  if flask db upgrade; then
    echo "✅  Upgrade succeeded after recovery"
  else
    echo "❌  Final Alembic upgrade failed – aborting deploy" >&2
    exit 1
  fi
fi

###############################################################################
# 3. Seed / update RBAC data
###############################################################################
echo "👥  Seeding roles / permissions…"
python - <<'PY'
from app import app, initialize_roles_permissions
with app.app_context():
    initialize_roles_permissions()
    print("✅  RBAC initialised")
PY

###############################################################################
# 4. Ensure admin user exists
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
# 5. Launch Gunicorn
###############################################################################
echo "🚀  Launching Gunicorn…"
exec gunicorn --workers 4 --bind 0.0.0.0:${PORT:-8000} app:app
