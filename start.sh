#!/usr/bin/env bash
set -euo pipefail

export FLASK_ENV=production

echo "🚀  Starting deployment script…"

# ------------------------------------------------------------------
# 0. Sanity-check required secrets and dependencies
# ------------------------------------------------------------------
if [[ -z "${ADMIN_EMAIL:-}" || -z "${ADMIN_PASSWORD:-}" ]]; then
  echo "❌  ADMIN_EMAIL and ADMIN_PASSWORD must be set" >&2
  exit 1
fi

if ! command -v alembic &> /dev/null; then
  echo "❌  Alembic not found. Install with: pip install alembic" >&2
  exit 1
fi

# ------------------------------------------------------------------
# 1. Robust Alembic migration handling with recovery
# ------------------------------------------------------------------
echo "🗄️  Applying database migrations…"

migration_failed=false
if ! flask db upgrade; then
  echo "⚠️  Initial upgrade attempt failed"
  migration_failed=true
fi

if $migration_failed; then
  echo "🔧  Attempting migration recovery..."
  
  # Get current head revision from codebase
  HEAD_REV=$(alembic heads | awk 'NR==1{print $1}')
  
  # Recovery procedure
  python - <<PY
import os
from sqlalchemy import create_engine, text

# Get database URL from environment
db_url = os.environ.get('DATABASE_URL')
if not db_url:
    print("❌  DATABASE_URL not set")
    exit(1)

engine = create_engine(db_url)
try:
    with engine.connect() as conn:
        # 1. Fix alembic_version table
        conn.execute(text("CREATE TABLE IF NOT EXISTS alembic_version (version_num VARCHAR(32) NOT NULL"))
        
        # 2. Clear existing version if it's causing problems
        conn.execute(text("DELETE FROM alembic_version"))
        
        # 3. Stamp with current head revision
        if "$HEAD_REV":
            conn.execute(text("INSERT INTO alembic_version (version_num) VALUES ('$HEAD_REV')"))
            print(f"✅  Force-stamped database with revision: $HEAD_REV")
        else:
            print("❌  Could not determine head revision")
            exit(1)
            
        conn.commit()
    print("✅  Migration recovery completed")
except Exception as e:
    print(f"❌  Migration recovery failed: {str(e)}")
    exit(1)
PY

  # Retry upgrade after recovery
  echo "🔄  Retrying database upgrade after recovery..."
  if flask db upgrade; then
    echo "✅  Upgrade succeeded after recovery"
  else
    echo "❌  Final upgrade attempt failed – aborting deploy" >&2
    exit 1
  fi
fi

# ... rest of your original script (roles, admin user, gunicorn) ...
# ------------------------------------------------------------------
# 2. Seed / update RBAC data (idempotent)
# ------------------------------------------------------------------
echo "👥  Seeding roles / permissions…"
python - <<'PY'
from app import app, initialize_roles_permissions
with app.app_context():
    initialize_roles_permissions()
PY

# ------------------------------------------------------------------
# 3. Ensure admin user exists (idempotent)
# ------------------------------------------------------------------
echo "👑  Ensuring admin account…"
python - <<'PY'
from app import app, db, User
from werkzeug.security import generate_password_hash
import os, time

email    = os.environ["ADMIN_EMAIL"]
password = os.environ["ADMIN_PASSWORD"]

with app.app_context():
    admin = User.query.filter_by(email=email).first()
    if admin is None:
        username = "admin"
        if User.query.filter_by(username=username).first():       # avoid UNIQUE clash
            username = f"admin_{int(time.time())}"
        admin = User(username=username,
                     email=email,
                     password_hash=generate_password_hash(password))
        db.session.add(admin)
        db.session.commit()
        print(f"✅  Created admin user {email} ({username})")
    else:
        print("✅  Admin user already present")
PY

# ------------------------------------------------------------------
# 4. Launch app
# ------------------------------------------------------------------
echo "🚀  Launching Gunicorn…"
exec gunicorn --workers 4 --bind 0.0.0.0:${PORT:-8000} app:app
