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

# Check for existing admin user
echo "🔍 Checking admin configuration..."
ADMIN_EXISTS=$(python -c "
from app import app, User
with app.app_context():
    admin = User.query.filter_by(email='$ADMIN_EMAIL').first()
    if admin:
        # Check if another user already has 'admin' username
        conflict = User.query.filter(User.username=='admin', User.id != admin.id).first()
        if conflict:
            print('conflict')
        else:
            print('exists')
    else:
        print('missing')
")

# Handle admin creation based on check results
case "$ADMIN_EXISTS" in
    "exists")
        echo "✅ Admin user already exists - skipping creation"
        ;;
    "conflict")
        echo "⚠️  Username conflict detected - updating admin username"
        python -c "
from app import app, User
with app.app_context():
    admin = User.query.filter_by(email='$ADMIN_EMAIL').first()
    if admin:
        # Append timestamp to make username unique
        import time
        new_username = f'admin_{int(time.time())}'
        admin.username = new_username
        db.session.commit()
        print(f'✅ Updated admin username to: {new_username}')
"
        ;;
    "missing")
        echo "👑 Creating admin user: $ADMIN_EMAIL"
        flask create-admin
        ;;
    *)
        echo "⚠️  Unknown admin status - skipping admin creation"
        ;;
esac

# Start the Flask app
echo "🚀 Starting Flask application..."
exec gunicorn --workers 4 --bind 0.0.0.0:$PORT app:app