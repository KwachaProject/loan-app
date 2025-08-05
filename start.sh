#!/usr/bin/env bash
set -u  # Exit on unset variables

export FLASK_ENV=production
export FLASK_APP=app.py
echo "🚀 Starting deployment script…"

###############################################################################
# 1. Ensure critical DB columns exist
###############################################################################
echo "🧱 Checking and patching schema if needed…"

python - <<'PY'
import os
import psycopg2

def column_exists(cursor, table, column):
    cursor.execute("""
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = %s AND column_name = %s
    """, (table, column))
    return cursor.fetchone() is not None

def add_column(cursor, table, column, ddl):
    try:
        cursor.execute(f"ALTER TABLE {table} ADD COLUMN {column} {ddl}")
        print(f"✅  Added {table}.{column}")
    except Exception as e:
        print(f"❌  Failed to add {table}.{column}: {e}")

def main():
    try:
        conn = psycopg2.connect(os.environ["DATABASE_URL"], sslmode="require")
        cursor = conn.cursor()

        # Table: loan_applications
        loan_columns = {
            "current_balance": "NUMERIC(12,2) DEFAULT 0.0",
            "top_up_balance": "NUMERIC(12,2) DEFAULT 0.0",
            "settlement_balance": "NUMERIC(12,2) DEFAULT 0.0",
            "settlement_type": "VARCHAR(50)",
            "settling_institution": "VARCHAR(255)",
            "settlement_reason": "TEXT",
            "parent_loan_id": "INTEGER"
        }

        for col, ddl in loan_columns.items():
            if column_exists(cursor, "loan_applications", col):
                print(f"✔️  loan_applications.{col} exists")
            else:
                print(f"➕  Adding loan_applications.{col}")
                add_column(cursor, "loan_applications", col, ddl)

        # Table: payment_allocations
        payment_columns = {
            "settlement_interest": "NUMERIC(12,2) DEFAULT 0.0"
        }

        for col, ddl in payment_columns.items():
            if column_exists(cursor, "payment_allocations", col):
                print(f"✔️  payment_allocations.{col} exists")
            else:
                print(f"➕  Adding payment_allocations.{col}")
                add_column(cursor, "payment_allocations", col, ddl)

        conn.commit()
        print("✅  Schema verification complete")

    except Exception as e:
        print(f"❌  Schema verification failed: {e}")
    finally:
        if 'conn' in locals():
            conn.close()

main()
PY

###############################################################################
# 2. Alembic Migration Head Management
###############################################################################
echo "📌  Managing Alembic head revision…"

HEAD_REV=$(alembic heads | awk 'NR==1{print $1}' | xargs echo -n)
if [ -z "$HEAD_REV" ]; then
    echo "⚠️  No head revision found, using default"
    HEAD_REV="5ada732a06fc"  # ← Set this to your last known good revision
fi

alembic stamp "$HEAD_REV" || echo "⚠️  Alembic stamp failed"

###############################################################################
# 3. Initialize Roles & Admin
###############################################################################
echo "👥  Initializing RBAC roles and permissions…"
python -c "from app import app, initialize_roles_permissions; \
with app.app_context(): \
    initialize_roles_permissions(); \
    print('✅  RBAC initialized')" || echo "⚠️  RBAC init failed"

echo "👑  Ensuring admin user…"
python -c "import os, time; \
from app import app, db, User; \
from werkzeug.security import generate_password_hash; \
with app.app_context(): \
    email = os.environ['ADMIN_EMAIL']; \
    password = os.environ['ADMIN_PASSWORD']; \
    admin = User.query.filter_by(email=email).first(); \
    if admin: print('✅  Admin already exists') \
    else: \
        username = f'admin_{int(time.time())}'; \
        admin = User(username=username, email=email, password_hash=generate_password_hash(password)); \
        db.session.add(admin); db.session.commit(); \
        print(f'✅  Created admin {email}')" || echo "⚠️  Admin creation failed"

###############################################################################
# 4. Start Gunicorn
###############################################################################
echo "🚀  Launching Gunicorn…"
exec gunicorn --workers 4 --bind 0.0.0.0:${PORT:-8000} --access-logfile - app:app
