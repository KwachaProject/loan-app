#!/bin/bash
# -----------------  start.sh  -----------------

export FLASK_ENV=production
set -e

echo "🚀  Starting deployment script..."
echo "🔍  Checking environment variables..."
if [[ -z "$ADMIN_EMAIL" || -z "$ADMIN_PASSWORD" ]]; then
  echo "❌  ADMIN_EMAIL and ADMIN_PASSWORD must be set"
  exit 1
fi

echo "🛠️   Handling database schema..."

# ---------- helper: does a table exist? ----------
table_exists() {
  local tbl="$1"
  python - <<PY
from app import app, db
with app.app_context():
    print('exists' if db.engine.dialect.has_table(db.engine.connect(), '$tbl') else 'missing')
PY
}

# ---------- create core tables if they’re missing ----------
echo "🔍  Checking core tables..."
for TBL in user loan payment; do
  if [[ "$(table_exists "$TBL")" == "missing" ]]; then
    echo "🛠️   Creating missing table: $TBL"
    python - <<PY
from app import app, db, User, Loan, Payment
models = {'user': User, 'loan': Loan, 'payment': Payment}
with app.app_context():
    models['$TBL'].__table__.create(db.engine)
    print("✅  Created $TBL table")
PY
  fi
done

# ---------- create ‘vote’ table if it isn’t there ----------
if [[ "$(table_exists vote)" == "missing" ]]; then
  echo "🛠️   Creating vote table..."
  python - <<PY
from app import app, db
with app.app_context():
    db.create_all()
    print("✅  Created vote table")
PY
fi

# ---------- roles / permissions ----------
echo "👥  Initializing roles and permissions..."
python - <<PY
from app import app, initialize_roles_permissions
with app.app_context():
    initialize_roles_permissions()
    print("✅  Roles and permissions initialized")
PY

# ---------- admin user ----------
echo "🔍  Checking for existing admin user..."
ADMIN_EXISTS=$(python - <<PY
from app import app, db, User
with app.app_context():
    print('yes' if User.query.filter_by(username='admin').first() else 'no')
PY
)

if [[ "$ADMIN_EXISTS" == "yes" ]]; then
  echo "✅  Admin already present – skipping creation."
else
  echo "👑  Creating admin user: $ADMIN_EMAIL"
  flask create-admin --username admin --email "$ADMIN_EMAIL" --password "$ADMIN_PASSWORD"
fi

# ---------- launch ----------
echo "🚀  Starting Gunicorn..."
exec gunicorn --workers 4 --bind "0.0.0.0:${PORT:-5000}" app:app
# -----------------------------------------------------------
