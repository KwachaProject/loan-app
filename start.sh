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

# Function to check if table exists
table_exists() {
    local table_name="$1"
    python -c "
from app import create_app, db
app = create_app()
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
from app import create_app, db
app = create_app()
with app.app_context():
    if '$table' == 'user':
        from app.models import User
        User.__table__.create(db.engine)
    elif '$table' == 'loan':
        from app.models import Loan
        Loan.__table__.create(db.engine)
    elif '$table' == 'payment':
        from app.models import Payment
        Payment.__table__.create(db.engine)
    print('✅ Created $table table')
        "
    fi
done

# Create the vote table if missing
if [ "$(table_exists vote)" = "missing" ]; then
    echo "🛠️  Creating vote table..."
    python -c "
from app import create_app, db
app = create_app()
with app.app_context():
    db.create_all()
    print('✅ Created vote table')
    "
fi

# Initialize roles and permissions
echo "👥 Initializing roles and permissions..."
python -c "
from app import create_app, initialize_roles_permissions
app = create_app()
with app.app_context():
    initialize_roles_permissions()
    print('✅ Roles and permissions initialized')
"

# Create/update admin user
echo "👑 Configuring admin user: $ADMIN_EMAIL"
flask create-admin || {
    echo "🔄 Retrying admin creation with force..."
    flask create-admin --force
}

# Verify admin creation
echo "🔒 Verifying admin account..."
if flask create-admin | grep -q -E "created|promoted|exists"; then
    echo "✅ Admin account verified"
else
    echo "⚠️  Admin verification failed - continuing anyway"
fi

# Start the Flask app
echo "🚀 Starting Flask application..."
exec gunicorn --workers 4 --bind 0.0.0.0:$PORT app:app