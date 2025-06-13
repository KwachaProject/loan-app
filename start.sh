#!/usr/bin/env bash
# ────────────────────────────────────────────────────────────────────
#  start.sh  –  Render deployment entry‑point for the Flask loan‑app
# --------------------------------------------------------------------
#  • Runs all Alembic migrations (flask db upgrade)
#  • Adds any legacy tables / columns that might still be missing
#  • Seeds roles / permissions
#  • Ensures a single admin user, using $ADMIN_EMAIL / $ADMIN_PASSWORD
#  • Finally launches Gunicorn
# ────────────────────────────────────────────────────────────────────

set -e
export FLASK_ENV=production

echo "🚀  Starting deployment script..."
echo "🔍  Checking environment variables…"
if [[ -z "$ADMIN_EMAIL" || -z "$ADMIN_PASSWORD" ]]; then
  echo "❌  ADMIN_EMAIL and ADMIN_PASSWORD must be set" ; exit 1
fi

# ------------------------------------------------------------------
# 1️⃣  Apply every Alembic migration
# ------------------------------------------------------------------
echo "🗄️  Running 'flask db upgrade'…"
flask db upgrade

# ------------------------------------------------------------------
# 2️⃣  OPTIONAL safety‑net: create tables / columns that might still
#     be missing (useful on very old prod DBs)
# ------------------------------------------------------------------
echo "🛠️   Verifying core schema…"

table_exists() {
  local tbl=$1
  python - <<PY
from app import app, db
with app.app_context():
    print('exists' if db.engine.dialect.has_table(db.engine, '$tbl') else 'missing')
PY
}

column_exists() {
  local tbl=$1 col=$2
  python - <<PY
from app import app, db
with app.app_context():
    q = """
        SELECT 1 FROM information_schema.columns
        WHERE table_name = '$tbl' AND column_name = '$col'
    """
    print('exists' if db.session.execute(q).scalar() else 'missing')
PY
}

# Core tables we absolutely need
for tbl in user loan payment loan_applications; do
  if [[ "$(table_exists "$tbl")" == "missing" ]]; then
    echo "🧱  Creating missing table: $tbl"
    python - <<PY
from app import app, db
with app.app_context():
    db.create_all()        # create *any* missing table
    print("✅  Created table: $tbl")
PY
  fi
done

# Patch legacy columns on loan_applications (only if still missing)
declare -A PATCH_COLS=(
  [current_balance]="NUMERIC(12,2) DEFAULT 0.0"
  [top_up_balance]="NUMERIC(12,2)"
  [settlement_balance]="NUMERIC(12,2)"
  [settlement_type]="VARCHAR(50)"
  [settling_institution]="VARCHAR(255)"
  [settlement_reason]="TEXT"
  [parent_loan_id]="INTEGER"
)

for col in "${!PATCH_COLS[@]}"; do
  if [[ "$(column_exists loan_applications "$col")" == "missing" ]]; then
    echo "➕  Adding column '$col' to loan_applications"
    python - <<PY
from app import app, db
with app.app_context():
    db.engine.execute(
        "ALTER TABLE loan_applications ADD COLUMN $col ${PATCH_COLS[$col]}"
    )
    print("   ↳ added")
PY
  fi
done

# ------------------------------------------------------------------
# 3️⃣  Seed roles / permissions
# ------------------------------------------------------------------
echo "👥  Initialising roles & permissions…"
python - <<PY
from app import app, initialize_roles_permissions
with app.app_context():
    initialize_roles_permissions()
    print("✅  Roles & permissions ready")
PY

# ------------------------------------------------------------------
# 4️⃣  Ensure exactly one admin user
# ------------------------------------------------------------------
echo "🔍  Ensuring admin user…"
python - <<PY
from app import app, db, User
from werkzeug.security import generate_password_hash
import os, time
email = os.environ["ADMIN_EMAIL"]
password = os.environ["ADMIN_PASSWORD"]

with app.app_context():
    admin = User.query.filter_by(email=email).first()
    if admin:
        print("   ↳ Admin already exists – leaving as‑is")
    else:
        # Avoid duplicate username 'admin'
        if User.query.filter_by(username='admin').first():
            username = f"admin_{int(time.time())}"
            print(f"   ↳ 'admin' username taken; using {username}")
        else:
            username = "admin"
        admin = User(username=username, email=email,
                     password_hash=generate_password_hash(password))
        db.session.add(admin); db.session.commit()
        print("✅  Admin user created")
PY

# ------------------------------------------------------------------
# 5️⃣  Launch Gunicorn
# ------------------------------------------------------------------
echo "🚀  Starting Gunicorn…"
exec gunicorn --workers 4 --bind 0.0.0.0:${PORT:-8000} app:app
