#!/bin/bash

export FLASK_ENV=production
set -e  # Exit immediately if a command exits with a non-zero status.

echo "Starting deployment script..."

# Validate environment variables
echo "Checking environment variables..."
if [[ -z "$ADMIN_EMAIL" || -z "$ADMIN_PASSWORD" ]]; then
    echo "❌ ERROR: ADMIN_EMAIL and ADMIN_PASSWORD must be set"
    exit 1
fi

# Handle broken migration history once
echo "Resetting migration history if needed..."
if [ ! -f ".migration_reset_complete" ]; then
    echo "Performing migration reset..."

    # Backup migration directory
    rm -rf migrations_backup
    mkdir migrations_backup
    cp -r migrations/versions migrations_backup/ || echo "No existing versions to back up"

    # Reinitialize migrations
    rm -rf migrations
    flask db init
    flask db migrate -m "Reset migration history"
    flask db stamp head

    touch .migration_reset_complete
    echo "Migration reset complete"
fi

# Migration folder must exist
echo "Checking migration directory..."
if [ ! -d "migrations/versions" ]; then
    echo "Initializing migration folder..."
    flask db init
fi

# Handle multiple heads (merge if necessary)
echo "Checking for multiple Alembic heads..."
HEAD_COUNT=$(flask db heads | wc -l)
if [ "$HEAD_COUNT" -gt 1 ]; then
    echo "⚠️  Multiple heads detected. Merging them..."
    flask db merge -m "Auto-merge multiple heads" $(flask db heads | tr '\n' ' ')
fi

# Try upgrading DB
echo "Applying database upgrades..."
if ! flask db upgrade; then
    echo "⚠️  Migration failed - attempting to stamp DB to head"
    flask db stamp head
    flask db upgrade || {
        echo "❌ Migration still failed after stamping"
        exit 1
    }
fi

# Initialize roles and permissions
echo "Initializing roles and permissions..."
python -c "from app import initialize_roles_permissions; initialize_roles_permissions()"

# Create/update admin user
echo "Configuring admin user: $ADMIN_EMAIL"
if flask create-admin 2>&1 | grep -q "use --force to update password"; then
    echo "⚠️  Admin exists. Forcing password update..."
    flask create-admin --force
else
    flask create-admin
fi

# Verify admin creation
echo "Verifying admin account..."
if flask create-admin | grep -q -E "created|promoted|exists"; then
    echo "✅ Admin account verified"
else
    echo "❌ CRITICAL: Admin account setup failed"
    exit 1
fi

# Start the Flask app
echo "Starting Flask application..."
exec gunicorn --workers 4 --bind 0.0.0.0:$PORT app:app
