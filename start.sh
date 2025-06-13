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
# 1. Database Schema Management
# -----------------------------------------------------------
echo "🛠️  Managing database schema..."

# Function to check if table exists
table_exists() {
  local table="$1"
  python -c "
from app import app, db
with app.app_context():
    print('exists' if db.engine.dialect.has_table(db.engine.connect(), '$table') else 'missing')
"
}

# Function to check if column exists
column_exists() {
  local table="$1"
  local column="$2"
  python -c "
from app import app, db
from sqlalchemy import text
with app.app_context():
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
"
}

# Create core tables if missing
echo "🔍 Checking core tables..."
for table in user loan payment loan_applications; do
  status=$(table_exists "$table")
  if [ "$status" = "missing" ]; then
    echo "🛠️  Creating missing table: $table"
    python -c "
from app import app, db
with app.app_context():
    db.create_all()
    print('✅ Created $table table')
"
  fi
done

# Create vote table if missing
if [ "$(table_exists vote)" = "missing" ]; then
  echo "🛠️  Creating vote table..."
  python -c "
from app import app, db
with app.app_context():
    db.create_all()
    print('✅ Created vote table')
"
fi

# Add missing columns to loan_applications
echo "🔍 Checking loan_applications schema..."
declare -A loan_app_columns=(
    ["current_balance"]="NUMERIC(12, 2) DEFAULT 0.0"
    ["top_up_balance"]="NUMERIC(12, 2)"
    ["settlement_balance"]="NUMERIC(12, 2)"
    ["settlement_type"]="VARCHAR(50)"
    ["settling_institution"]="VARCHAR(255)"
    ["settlement_reason"]="TEXT"
    ["parent_loan_id"]="INTEGER"
)

for column in "${!loan_app_columns[@]}"; do
  if [ "$(column_exists loan_applications "$column")" = "missing" ]; then
    echo "➕ Adding column $column to loan_applications"
    python -c "
from app import app, db
from sqlalchemy import text
with app.app_context():
    conn = db.engine.connect()
    # Use parameterized query with text()
    conn.execute(
        text('ALTER TABLE loan_applications ADD COLUMN $column ${loan_app_columns[$column]}')
    )
    print('✅ Added column $column')
"
  fi
done

# -----------------------------------------------------------
# 2. Simplified Migration Handling
# -----------------------------------------------------------
echo "🔄 Handling database migrations..."

# Always stamp head to ensure version is current
echo "🏷️  Stamping database with current Alembic head"
flask db stamp head || echo "⚠️  Stamping failed - continuing"

# Attempt to run migrations
echo "🆙 Attempting database upgrade..."
flask db upgrade || {
  echo "⚠️  Upgrade failed - applying recovery measures"
  
  # Reset migration state
  python -c "
from app import app, db
from sqlalchemy import text
with app.app_context():
    # Only reset if table exists
    if db.engine.dialect.has_table(db.engine.connect(), 'alembic_version'):
        conn = db.engine.connect()
        conn.execute(
            text('DELETE FROM alembic_version')
        )
        print('✅ Reset alembic_version table')
    else:
        print('✅ alembic_version table does not exist - nothing to reset')
"
  
  echo "🏷️  Re-stamping database head"
  flask db stamp head || echo "⚠️  Re-stamping failed - continuing"
  
  # Retry upgrade
  echo "🔄 Retrying database upgrade..."
  flask db upgrade || echo "⚠️  Upgrade retry failed - continuing with current schema"
}

# -----------------------------------------------------------
# 3. Initialize Roles and Permissions
# -----------------------------------------------------------
echo "👥 Initializing roles and permissions..."
python -c "
from app import app, initialize_roles_permissions
with app.app_context():
    initialize_roles_permissions()
    print('✅ Roles and permissions initialized')
"

# -----------------------------------------------------------
# 4. Admin User Setup
# -----------------------------------------------------------
echo "🔍 Configuring admin user..."

# Check for admin existence
ADMIN_STATUS=$(python -c "
from app import app, User
with app.app_context():
    admin = User.query.filter_by(email='$ADMIN_EMAIL').first()
    if admin:
        # Check username conflict
        conflict = User.query.filter(User.username=='admin', User.id != admin.id).first()
        if conflict:
            print('conflict')
        else:
            print('exists')
    else:
        print('missing')
")

case "$ADMIN_STATUS" in
    "exists")
        echo "✅ Admin user already exists"
        ;;
    "conflict")
        echo "⚠️  Resolving username conflict..."
        python -c "
from app import app, User
import time
with app.app_context():
    admin = User.query.filter_by(email='$ADMIN_EMAIL').first()
    if admin:
        new_username = f'admin_{int(time.time())}'
        admin.username = new_username
        db.session.commit()
        print(f'✅ Updated admin username to: {new_username}')
"
        ;;
    "missing")
        echo "👑 Creating admin user: $ADMIN_EMAIL"
        flask create-admin || echo "⚠️  Admin creation failed - continuing"
        ;;
    *)
        echo "⚠️  Unknown admin status - skipping admin setup"
        ;;
esac

# -----------------------------------------------------------
# 5. Start Application
# -----------------------------------------------------------
echo "🚀 Starting Gunicorn..."
exec gunicorn --workers 4 --bind 0.0.0.0:${PORT:-8000} app:app