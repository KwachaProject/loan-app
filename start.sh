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

# Reset migration history if needed
echo "Resetting migration history..."
if [ ! -f ".migration_reset_complete" ]; then
    echo "Performing migration reset..."
    
    # Backup current migration directory
    rm -rf migrations_backup
    mkdir migrations_backup
    cp -r migrations/versions migrations_backup/
    
    # Reset the migration repository
    rm -rf migrations
    flask db init
    
    # Create a new initial migration
    flask db migrate -m "Reset migration history"
    
    # Stamp the database with the new revision
    flask db stamp head
    
    # Create marker file to prevent future resets
    touch .migration_reset_complete
    
    echo "Migration reset complete"
fi

# Database migration handling
echo "Handling database migrations..."
if [ ! -d "migrations/versions" ]; then
    flask db init
fi

# Apply database upgrades
echo "Applying database upgrades..."
if flask db upgrade; then
    echo "Database upgrade successful"
else
    echo "⚠️  Migration failed - stamping database with head revision"
    flask db stamp head
    flask db upgrade
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