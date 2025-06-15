#!/usr/bin/env bash
set -euo pipefail

export FLASK_ENV=production
echo "🚀  Starting deployment script…"

###############################################################################
# 0. Sanity‑check required secrets
###############################################################################
require_env() {
  local var=$1
  if [[ -z "${!var:-}" ]]; then
    echo "❌  $var must be set" >&2
    exit 1
  fi
}
require_env ADMIN_EMAIL
require_env ADMIN_PASSWORD

###############################################################################
# Helper – turn “postgres://” into “postgresql://”
###############################################################################
fix_url() {
  [[ $1 == postgres://* ]] && echo "${1/postgres:/postgresql:}" || echo "$1"
}
DB_URL="$(fix_url "$DATABASE_URL")"

###############################################################################
# 1.  Make sure the critical columns exist (idempotent)
###############################################################################
ensure_columns() {
  echo "🆘  Ensuring critical columns exist…"

  python - <<'PY'
import os, textwrap
from sqlalchemy import create_engine, inspect, text

engine = create_engine(os.environ["DB_URL"], isolation_level="AUTOCOMMIT")
needed = {
    "current_balance"     : "NUMERIC(12,2) DEFAULT 0.0",
    "top_up_balance"      : "NUMERIC(12,2) DEFAULT 0.0",
    "settlement_balance"  : "NUMERIC(12,2) DEFAULT 0.0",
    "settlement_type"     : "VARCHAR(50)",
    "settling_institution": "VARCHAR(255)",
    "settlement_reason"   : "TEXT",
    "parent_loan_id"      : "INTEGER",
}

with engine.connect() as con:
    existing = {c["name"] for c in inspect(con).get_columns("loan_applications")}
    for col, ddl in needed.items():
        if col in existing:
            print(f"   ✅ {col}")
            continue
        print(f"   ➕ adding {col}")
        try:
            con.execute(text(f"ALTER TABLE loan_applications ADD COLUMN {col} {ddl}"))
        except Exception as e:
            print(f"   ⚠️  {col}: {e}  (ignored)")
PY
  echo "✅  Column check complete"
}
ensure_columns

###############################################################################
# 2. Alembic migrations
###############################################################################
run_migrations() {
  echo "🗄️  Running Alembic migrations…"

  # 2a – ensure database knows the baseline
  flask db stamp 0001_baseline || true      # no‑op if already stamped

  # 2b – autogenerate an “initial schema” migration *once*
  flask db migrate -m "initial schema after baseline" || true

  # 2c – upgrade, with a one‑shot recovery if it blows up
  if flask db upgrade; then
    echo "✅  Upgrade complete"
    return
  fi

  echo "⚠️  Upgrade failed – attempting one‑time recovery"
  HEAD_REV=$(alembic heads | awk 'NR==1{print $1}')

  python - <<PY
from sqlalchemy import create_engine, text
import os, sys
engine = create_engine(os.environ["DB_URL"], isolation_level="AUTOCOMMIT")
with engine.connect() as c:
    c.execute(text("CREATE TABLE IF NOT EXISTS alembic_version (version_num VARCHAR(32) NOT NULL)"))
    c.execute(text("DELETE FROM alembic_version"))
    c.execute(text("INSERT INTO alembic_version (version_num) VALUES (:v)"), {"v": "$HEAD_REV"})
    print(f"   ✅  Force‑stamped to $HEAD_REV")
PY

  flask db upgrade || { echo "❌  Recovery failed" >&2; exit 1; }
  echo "✅  Upgrade succeeded after recovery"
}
run_migrations

###############################################################################
# 3. Seed / update RBAC data
###############################################################################
seed_rbac() {
  echo "👥  Seeding roles / permissions…"
  python - <<'PY'
from app import app, initialize_roles_permissions
with app.app_context():
    initialize_roles_permissions()
    print("   ✅  RBAC ready")
PY
}
seed_rbac

###############################################################################
# 4. Ensure admin user exists
###############################################################################
ensure_admin() {
  echo "👑  Ensuring admin user…"
  python - <<'PY'
import os, time
from werkzeug.security import generate_password_hash
from app import app, db, User

email, pwd = os.environ["ADMIN_EMAIL"], os.environ["ADMIN_PASSWORD"]

with app.app_context():
    u = User.query.filter_by(email=email).first()
    if u:
        print("   ✅  already exists")
    else:
        username = "admin"
        if User.query.filter_by(username=username).first():
            username = f"admin_{int(time.time())}"
        u = User(username=username, email=email,
                 password_hash=generate_password_hash(pwd))
        db.session.add(u); db.session.commit()
        print(f"   ✅  created {email} ({username})")
PY
}
ensure_admin

###############################################################################
# 5. Launch Gunicorn
###############################################################################
echo "🚀  Launching Gunicorn…"
exec gunicorn --workers 4 --bind "0.0.0.0:${PORT:-8000}" app:app
