#!/bin/bash

export FLASK_ENV=production
set -e

echo "🚀 Starting deployment script..."
echo "🔍 Checking environment variables..."

if [[ -z "$ADMIN_EMAIL" || -z "$ADMIN_PASSWORD" ]]; then
    echo "❌ ERROR: ADMIN_EMAIL and ADMIN_PASSWORD must be set"
    exit 1
fi

echo "🛠️  Handling database schema..."

# Function to check if a table exists
table_exists() {
    local table_name="$1"
    python -c "
from app import app, db
with app.app_context():
    if db.engine.dialect.has_table(db.engine.connect(), '$table_name'):
        print('exists')
    else:
        print('missing')
"
}

# Create core tables if missing
echo "🔍 Checking core tables..."
for table in "user" "loan" "payment"; do
    if [ "$(table_exists $table)" = "missing" ]; then
        echo "🛠️  Creating missing table: $table"
        python -c "
from app import app, db, User, Loan, Payment
with app.app_context():
    model_map = {
        'user': User,
        'loan': Loan,
        'payment': Payment
    }
    model = model_map.get('$table')
    if model:
        model.__table__.create(db.engine)
        print('✅ Created $table table')
"
    fi
done

# Create the vote table if missing
if [ "$(table_exists vote)" = "missing" ]; then
    echo "🛠️  Creating vote table..."
    python -c "
from app import app, db
with app.app_context():
    db.create_all()
    print('✅ Created vote table')
"
fi

# Initialize roles and permissions
echo "👥 Initializing roles and permissions..."
python -c "
from app import app, initialize_roles_permissions
with app.app_context():
    initialize_roles_permissions()
    print('✅ Roles and permissions initialized')
"

# Check if admin user already exists
echo "🔍 Checking for existing admin user..."
ADMIN_EXISTS=$(python -c "
from app import app, User
with app.app_context():
    if User.query.filter_by(email='$ADMIN_EMAIL').first():
        print('exists')
    else:
        print('missing')
")

# Create admin user only if it doesn't exist
if [ "$ADMIN_EXISTS" = "exists" ]; then
    echo "✅ Admin user already exists - skipping creation"
else
    echo "👑 Creating admin user: $ADMIN_EMAIL"
    flask create-admin
fi

# Start the Flask app
echo "🚀 Starting Flask application..."
exec gunicorn --workers 4 --bind 0.0.0.0:$PORT app:app