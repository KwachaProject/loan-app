#!/bin/bash

export FLASK_ENV=production
set -e  # Exit immediately if a command exits with a non-zero status.

echo "Starting deployment script..."

# Run database migrations
echo "Applying database migrations..."
if [ ! -d "migrations/versions" ]; then
    flask db init
fi
flask db upgrade

# Initialize roles and permissions
echo "Initializing roles and permissions..."
python -c "from app import initialize_roles_permissions; initialize_roles_permissions()"

# Create admin user from environment variables
echo "Ensuring admin user exists from environment variables..."
flask create-admin

# Start the Flask app
echo "Starting Flask application..."
exec gunicorn --workers 4 --bind 0.0.0.0:$PORT app:app
