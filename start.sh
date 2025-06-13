#!/usr/bin/env bash
set -e
export FLASK_ENV=production

echo "🚀 Starting deployment script..."
echo "🔍 Checking environment variables..."
if [[ -z "$ADMIN_EMAIL" || -z "$ADMIN_PASSWORD" ]]; then
  echo "❌ ERROR: ADMIN_EMAIL and ADMIN_PASSWORD must be set" 
  exit 1
fi

# -----------------------------------------------------------
# 1. Database Schema Emergency Repair
# -----------------------------------------------------------
echo "🆘 PERFORMING DATABASE SCHEMA EMERGENCY REPAIR"

# Function to check if column exists
column_exists() {
  local table="$1"
  local column="$2"
  python -c "
from app import app, db
from sqlalchemy import text
with app.app_context():
    try:
        conn = db.engine.connect()
        result = conn.execute(
            text(\"\"\"SELECT EXISTS (
                SELECT 1 
                FROM information_schema.columns 
                WHERE table_name = :table AND column_name = :column
            )\"\"\"),
            {'table': '$table', 'column': '$column'}
        ).scalar()
        print('exists' if result else 'missing')
    except Exception as e:
        print('error')
"
}

# Critical columns that must exist
declare -A loan_app_columns=(
    ["current_balance"]="NUMERIC(12, 2) DEFAULT 0.0"
    ["top_up_balance"]="NUMERIC(12, 2)"
    ["settlement_balance"]="NUMERIC(12, 2)"
    ["settlement_type"]="VARCHAR(50)"
    ["settling_institution"]="VARCHAR(255)"
    ["settlement_reason"]="TEXT"
    ["parent_loan_id"]="INTEGER"
)

# Force creation of critical columns
for column in "${!loan_app_columns[@]}"; do
  echo "🔧 FORCING CREATION OF COLUMN: $column"
  python -c "
from app import app, db
from sqlalchemy import text
with app.app_context():
    try:
        # First try standard add
        conn = db.engine.connect()
        conn.execute(
            text('ALTER TABLE loan_applications ADD COLUMN IF NOT EXISTS $column ${loan_app_columns[$column]}')
        )
        print('✅ Column $column created or already exists')
    except Exception as e:
        print(f'⚠️  Standard creation failed: {str(e)}')
        print('🆘 Attempting emergency creation...')
        try:
            # Try without type constraints
            conn.execute(
                text('ALTER TABLE loan_applications ADD COLUMN $column TEXT')
            )
            print('✅ Created as TEXT type as fallback')
            # Try converting to proper type
            try:
                conn.execute(
                    text('ALTER TABLE loan_applications ALTER COLUMN $column TYPE ${loan_app_columns[$column]} USING $column::${loan_app_columns[$column]}')
                )
                print('✅ Converted to proper type')
            except:
                print('⚠️  Could not convert to proper type - using TEXT')
        except Exception as e2:
            print(f'❌ EMERGENCY CREATION FAILED: {str(e2)}')
"
done

# Verify critical columns
echo "🔍 VERIFYING CRITICAL COLUMNS..."
for column in "${!loan_app_columns[@]}"; do
  status=$(column_exists loan_applications "$column")
  if [ "$status" = "exists" ]; then
    echo "✅ Column $column exists"
  else
    echo "❌ CRITICAL FAILURE: Column $column is MISSING!"
    echo "   This will cause application failures. Manual intervention required."
  fi
done

# -----------------------------------------------------------
# 2. Database Migration Handling
# -----------------------------------------------------------
echo "🔄 Handling database migrations..."

# Check if alembic_version table exists
if [ "$(column_exists alembic_version version_num)" = "exists" ]; then
  echo "⏩ Alembic version table exists"
else
  echo "🆕 Creating alembic_version table if needed"
  python -c "
from app import app, db
from sqlalchemy import text
with app.app_context():
    if not db.engine.dialect.has_table(db.engine.connect(), 'alembic_version'):
        try:
            conn = db.engine.connect()
            conn.execute(
                text('CREATE TABLE alembic_version (version_num VARCHAR(32) NOT NULL)')
            )
            print('✅ Created alembic_version table')
        except Exception as e:
            print(f'⚠️  Creation failed: {str(e)}')
    else:
        print('✅ alembic_version already exists')
"
fi

echo "🏷️  Stamping database with current Alembic head"
flask db stamp head || echo "⚠️  Stamping failed - continuing"

echo "🆙 Attempting database upgrade..."
flask db upgrade || {
  echo "⚠️  Upgrade failed - resetting migration state"
  python -c "
from app import app, db
from sqlalchemy import text
with app.app_context():
    try:
        if db.engine.dialect.has_table(db.engine.connect(), 'alembic_version'):
            conn = db.engine.connect()
            conn.execute(text('DELETE FROM alembic_version'))
            print('✅ Reset alembic_version table')
    except Exception as e:
        print(f'⚠️  Reset failed: {str(e)}')
"
  echo "🔄 Retrying database upgrade..."
  flask db upgrade || echo "⚠️  Upgrade retry failed - continuing"
}

# -----------------------------------------------------------
# 3. Initialize Roles and Admin User
# -----------------------------------------------------------
echo "👥 Initializing roles and permissions..."
python -c "
from app import app, initialize_roles_permissions
with app.app_context():
    try:
        initialize_roles_permissions()
        print('✅ Roles and permissions initialized')
    except Exception as e:
        print(f'⚠️  Initialization failed: {str(e)}')
"

echo "🔍 Configuring admin user..."
python -c "
from app import app, db, User
from werkzeug.security import generate_password_hash
import os, time
email = os.environ['ADMIN_EMAIL']
password = os.environ['ADMIN_PASSWORD']

with app.app_context():
    try:
        admin = User.query.filter_by(email=email).first()
        if admin:
            # Resolve username conflict if needed
            conflict = User.query.filter(User.username=='admin', User.id != admin.id).first()
            if conflict:
                new_username = f'admin_{int(time.time())}'
                admin.username = new_username
                print(f'✅ Updated admin username to: {new_username}')
            else:
                print('✅ Admin user exists')
        else:
            # Create admin with unique username
            username = 'admin'
            if User.query.filter_by(username=username).first():
                username = f'admin_{int(time.time())}'
                
            admin = User(
                username=username,
                email=email,
                password_hash=generate_password_hash(password)
            )
            db.session.add(admin)
            print(f'✅ Created admin user: {email}')
        db.session.commit()
    except Exception as e:
        print(f'❌ CRITICAL: Admin setup failed: {str(e)}')
"

# -----------------------------------------------------------
# 4. Final Verification
# -----------------------------------------------------------
echo "🔍 FINAL SCHEMA VERIFICATION..."
python -c "
from app import app, db
from sqlalchemy import text
with app.app_context():
    print('--- Loan Applications Columns ---')
    try:
        result = db.engine.execute(text(\"\"\"
            SELECT column_name 
            FROM information_schema.columns 
            WHERE table_name = 'loan_applications'
        \"\"\"))
        columns = [row[0] for row in result]
        print('Found columns:', ', '.join(columns))
        
        # Check for critical columns
        critical_columns = ['current_balance', 'top_up_balance', 'settlement_balance']
        missing = [col for col in critical_columns if col not in columns]
        if missing:
            print(f'❌ MISSING CRITICAL COLUMNS: {", ".join(missing)}')
        else:
            print('✅ All critical columns present')
    except Exception as e:
        print(f'⚠️  Verification failed: {str(e)}')
    
    print('\\n--- Alembic Version ---')
    try:
        if db.engine.dialect.has_table(db.engine.connect(), 'alembic_version'):
            version = db.engine.execute(text('SELECT version_num FROM alembic_version')).scalar()
            print(f'Current version: {version}')
        else:
            print('❌ alembic_version table missing')
    except Exception as e:
        print(f'⚠️  Version check failed: {str(e)}')
"

# -----------------------------------------------------------
# 5. Start Application
# -----------------------------------------------------------
echo "🚀 Starting Gunicorn..."
exec gunicorn --workers 4 --bind 0.0.0.0:${PORT:-8000} app:app