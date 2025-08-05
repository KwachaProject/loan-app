#!/usr/bin/env bash
set -u  # Only exit on unset variables

export FLASK_ENV=production
export FLASK_APP=app.py
echo "🚀  Starting deployment script…"

# ... [sanity checks] ...

###############################################################################
# 1. Ensure critical columns exist (UPDATED)
###############################################################################
echo "🆘  Ensuring critical columns exist…"

python - <<'PY'
import os
import psycopg2
import sys

def main():
    try:
        conn = psycopg2.connect(os.environ["DATABASE_URL"], sslmode="require")
        cursor = conn.cursor()
        
        # 1. Check loan_applications table
        cursor.execute("""
            SELECT column_name 
            FROM information_schema.columns 
            WHERE table_name = 'loan_applications'
        """)
        existing_columns = {row[0] for row in cursor.fetchall()}
        
        LOAN_NEEDED = {
            "current_balance": "NUMERIC(12,2) DEFAULT 0.0",
            "top_up_balance": "NUMERIC(12,2) DEFAULT 0.0",
            "settlement_balance": "NUMERIC(12,2) DEFAULT 0.0",
            "settlement_type": "VARCHAR(50)",
            "settling_institution": "VARCHAR(255)",
            "settlement_reason": "TEXT",
            "parent_loan_id": "INTEGER"
        }
        
        for col, ddl in LOAN_NEEDED.items():
            if col in existing_columns:
                print(f"✅  loan_applications.{col} exists")
            else:
                print(f"⚠️  ADDING: loan_applications.{col}")
                try:
                    cursor.execute(f"ALTER TABLE loan_applications ADD COLUMN {col} {ddl}")
                    print(f"   → Added loan_applications.{col}")
                except Exception as e:
                    print(f"   ❌ Failed to add {col}: {str(e)}")
        
        # 2. Check payment_allocations table (CRITICAL FIX)
        cursor.execute("""
            SELECT column_name 
            FROM information_schema.columns 
            WHERE table_name = 'payment_allocations'
        """)
        payment_columns = {row[0] for row in cursor.fetchall()}
        
        PAYMENT_NEEDED = {
            "settlement_interest": "NUMERIC(12,2) DEFAULT 0.0"
        }
        
        for col, ddl in PAYMENT_NEEDED.items():
            if col in payment_columns:
                print(f"✅  payment_allocations.{col} exists")
            else:
                print(f"⚠️  ADDING: payment_allocations.{col}")
                try:
                    cursor.execute(f"ALTER TABLE payment_allocations ADD COLUMN {col} {ddl}")
                    print(f"   → Added payment_allocations.{col}")
                except Exception as e:
                    print(f"   ❌ Failed to add {col}: {str(e)}")
        
        conn.commit()
        return True
        
    except Exception as e:
        print(f"❌  Column check failed: {str(e)}")
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

# ... [version management code] ...

###############################################################################
# 3. Start Application Services
###############################################################################
echo "👥  Initializing roles and permissions…"
python -c "from app import app, initialize_roles_permissions; \
app.app_context().push(); \
initialize_roles_permissions(); \
print('✅  RBAC initialized')" \
|| echo "⚠️  RBAC initialization failed"

echo "👑  Ensuring admin account…"
python -c "import os, time; \
from app import app, db, User; \
from werkzeug.security import generate_password_hash; \
email = os.environ['ADMIN_EMAIL']; \
password = os.environ['ADMIN_PASSWORD']; \
app.app_context().push(); \
admin = User.query.filter_by(email=email).first(); \
print('✅  Admin already present') if admin else ( \
    username := 'admin_' + str(int(time.time())), \
    new_admin := User(username=username, email=email, \
                      password_hash=generate_password_hash(password)), \
    db.session.add(new_admin), \
    db.session.commit(), \
    print(f'✅  Created admin user {email} ({username})') \
)" \
|| echo "⚠️  Admin creation failed"

echo "🚀  Launching Gunicorn…"
exec gunicorn --workers 4 --bind 0.0.0.0:${PORT:-8000} --access-logfile - app:app