#!/usr/bin/env bash
set -u  # Only exit on unset variables - handle other errors manually

export FLASK_ENV=production
export FLASK_APP=app.py
echo "🚀  Starting deployment script…"

###############################################################################
# 0. Sanity‑check required secrets
###############################################################################
if [[ -z "${ADMIN_EMAIL:-}" || -z "${ADMIN_PASSWORD:-}" ]]; then
  echo "❌  ADMIN_EMAIL and ADMIN_PASSWORD must be set" >&2
  exit 1
fi

###############################################################################
# 1. Ensure critical columns exist
###############################################################################
echo "🆘  Ensuring critical columns exist…"

# Use simpler Python connection method
python - <<'PY'
import os
import psycopg2
import sys

def main():
    try:
        conn = psycopg2.connect(os.environ["DATABASE_URL"], sslmode="require")
        cursor = conn.cursor()
        
        # Check if loan_applications table exists
        cursor.execute("""
            SELECT column_name 
            FROM information_schema.columns 
            WHERE table_name = 'loan_applications'
        """)
        existing_columns = {row[0] for row in cursor.fetchall()}
        
        NEEDED = {
            "current_balance": "NUMERIC(12,2) DEFAULT 0.0",
            "top_up_balance": "NUMERIC(12,2) DEFAULT 0.0",
            "settlement_balance": "NUMERIC(12,2) DEFAULT 0.0",
            "settlement_type": "VARCHAR(50)",
            "settling_institution": "VARCHAR(255)",
            "settlement_reason": "TEXT",
            "parent_loan_id": "INTEGER"
        }
        
        for col, ddl in NEEDED.items():
            if col in existing_columns:
                print(f"✅  {col} already present")
            else:
                print(f"➕  Adding {col}")
                try:
                    cursor.execute(f"ALTER TABLE loan_applications ADD COLUMN {col} {ddl}")
                    print(f"   → Successfully added {col}")
                except Exception as e:
                    print(f"   ⚠️  Failed to add {col}: {str(e)}")
        
        conn.commit()
        print("✅  Column check complete")
        return True
        
    except Exception as e:
        print(f"❌  Database connection failed: {str(e)}")
        return False
    finally:
        if 'conn' in locals():
            conn.close()

if not main():
    print("⚠️  Proceeding without column verification")
PY

###############################################################################
# 2. Robust Alembic Version Management
###############################################################################
echo "🗄️  Managing Alembic version with error tolerance…"

# Get head revision safely
HEAD_REV=$(alembic heads | awk 'NR==1{print $1}' | xargs echo -n)
if [ -z "$HEAD_REV" ]; then
    echo "⚠️  Could not determine head revision - using default"
    HEAD_REV="5ada732a06fc"  # Use your known revision
fi

echo "🔧  Setting DB version to: $HEAD_REV"

# Simplified version management
python - <<PY
import os
import psycopg2
import sys

def set_alembic_version():
    try:
        conn = psycopg2.connect(os.environ["DATABASE_URL"], sslmode="require")
        cursor = conn.cursor()
        
        # Create version table if needed
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS alembic_version (
                version_num VARCHAR(32) NOT NULL PRIMARY KEY
            )
        """)
        
        # Set to current head
        cursor.execute("DELETE FROM alembic_version")
        cursor.execute("INSERT INTO alembic_version (version_num) VALUES (%s)", (HEAD_REV,))
        
        conn.commit()
        print(f"✅  Successfully set version to {HEAD_REV}")
        return True
        
    except Exception as e:
        print(f"❌  Version management failed: {str(e)}")
        return False
    finally:
        if 'conn' in locals():
            conn.close()

# Use shell variable
HEAD_REV = "$HEAD_REV"
if set_alembic_version():
    sys.exit(0)
else:
    sys.exit(1)
PY

# If version management failed, continue anyway
if [ $? -ne 0 ]; then
    echo "⚠️  Version management failed - proceeding anyway"
fi

###############################################################################
# 3. Start Application Services
###############################################################################
echo "👥  Initializing roles and permissions…"
python -c "from app import app, initialize_roles_permissions; \
with app.app_context(): initialize_roles_permissions(); print('✅  RBAC initialized')" \
|| echo "⚠️  RBAC initialization failed"

echo "👑  Ensuring admin account…"
python -c "import os, time; \
from app import app, db, User; \
from werkzeug.security import generate_password_hash; \
email = os.environ['ADMIN_EMAIL']; \
password = os.environ['ADMIN_PASSWORD']; \
with app.app_context(): \
    admin = User.query.filter_by(email=email).first(); \
    if admin: print('✅  Admin already present'); \
    else: \
        username = 'admin_' + str(int(time.time())); \
        new_admin = User(username=username, email=email, \
                         password_hash=generate_password_hash(password)); \
        db.session.add(new_admin); \
        db.session.commit(); \
        print(f'✅  Created admin user {email} ({username})')" \
|| echo "⚠️  Admin creation failed"

echo "🚀  Launching Gunicorn…"
exec gunicorn --workers 4 --bind 0.0.0.0:${PORT:-8000} --access-logfile - app:app