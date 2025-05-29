#!/bin/bash
export FLASK_ENV=production
set -e  # Exit immediately if a command exits with a non-zero status.

echo "Starting deployment script..."

# Initialize database migrations if needed
if [ ! -d "migrations" ]; then
    echo "Initializing database migrations..."
    flask db init
fi

# Apply database migrations
echo "Applying database migrations..."
flask db upgrade

# Initialize RBAC system
echo "Initializing RBAC system..."
flask init-rbac

# Create initial admin user with secure password
echo "Creating admin user..."
ADMIN_PASSWORD=$(openssl rand -base64 16)
export ADMIN_PASSWORD
flask create-admin
echo "Admin password: $ADMIN_PASSWORD"  # Only for initial setup, remove in production

# Start the Flask app
echo "Starting Flask application..."
exec gunicorn --workers 4 --bind 0.0.0.0:$PORT app:app