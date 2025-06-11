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

# Database migration handling
echo "Handling database migrations..."
if [ ! -d "migrations/versions" ]; then
    flask db init
fi

# Use head-based migration reset only if needed (safer than hard-coded version)
echo "Resetting migration state if needed..."
flask db stamp head 2>/dev/null || true

echo "Applying database upgrades..."
flask db upgrade

# Initialize roles and permissions
echo "Initializing roles and permissions..."
python -c "from app import initialize_roles_permissions; initialize_roles_permissions()"

# Create/update admin user with safety confirmation
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