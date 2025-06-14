#!/usr/bin/env bash
set -euo pipefail

export FLASK_ENV=production

echo "🚀  Starting deployment script…"

# ------------------------------------------------------------------
# 0. Sanity‑check required secrets
# ------------------------------------------------------------------
if [[ -z "${ADMIN_EMAIL:-}" || -z "${ADMIN_PASSWORD:-}" ]]; then
  echo "❌  ADMIN_EMAIL and ADMIN_PASSWORD must be set" >&2
  exit 1
fi

# ------------------------------------------------------------------
# 1. Run Alembic migrations
# ------------------------------------------------------------------
echo "🗄️  Applying database migrations…"
if ! flask db upgrade; then
  echo "❌  Alembic upgrade failed – aborting deploy" >&2
  exit 1
fi

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
