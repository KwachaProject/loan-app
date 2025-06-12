#!/bin/bash

export FLASK_ENV=production
set -e

echo "🚀 Starting deployment script..."
echo "🔍 Checking environment variables..."
if [[ -z "$ADMIN_EMAIL" || -z "$ADMIN_PASSWORD" ]]; then
    echo "❌ ERROR: ADMIN_EMAIL and ADMIN_PASSWORD must be set"
    exit 1
fi

echo "🛠️  Handling database migrations..."

# Check if migrations need to be reset
RESET_NEEDED=$(python -c "
from app import create_app, db
app = create_app()
with app.app_context():
    if not db.engine.has_table('alembic_version'):
        print('RESET_NEEDED')
    else:
        try:
            from flask_migrate import current
            current()
            print('OK')
        except:
            print('RESET_NEEDED')
")

# Perform migration reset if needed
if [ "$RESET_NEEDED" = "RESET_NEEDED" ]; then
    echo "🔄 Resetting migration history..."

    # Backup existing migrations
    rm -rf migrations_backup
    mkdir migrations_backup
    [ -d "migrations" ] && cp -r migrations/versions migrations_backup/

    # Reset the migration repository
    rm -rf migrations
    flask db init

    # Create a new initial migration
    flask db migrate -m "Reset migration history"

    # Stamp the database with the new revision
    flask db stamp head

    echo "✅ Migration reset complete"
fi

# Apply database upgrades
echo "⬆️ Applying database upgrades..."
if flask db upgrade; then
    echo "✅ Database upgrade successful"
else
    echo "⚠️  Database upgrade failed - stamping head"
    flask db stamp head
    flask db upgrade
fi

# Initialize roles and permissions
echo "👥 Initializing roles and permissions..."
python -c "from app import initialize_roles_permissions; initialize_roles_permissions()"

# Create/update admin user
echo "👑 Configuring admin user: $ADMIN_EMAIL"
if flask create-admin 2>&1 | grep -q "use --force to update password"; then
    echo "🔄 Admin exists. Forcing password update..."
    flask create-admin --force
else
    flask create-admin
fi

# Verify admin creation
echo "🔒 Verifying admin account..."
if flask create-admin | grep -q -E "created|promoted|exists"; then
    echo "✅ Admin account verified"
else
    echo "❌ CRITICAL: Admin account setup failed"
    exit 1
fi

# Start the Flask app
echo "🚀 Starting Flask application..."
exec gunicorn --workers 4 --bind 0.0.0.0:$PORT app:app
