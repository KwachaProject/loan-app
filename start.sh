# Deployment start script
#!/bin/bash
set -e  # Exit immediately if a command exits with a non-zero status.

echo "Starting deployment script..."

# Run database migrations using Alembic (via Flask-Migrate)
echo "Applying database migrations..."
flask db upgrade

# Initialize roles and permissions
echo "Initializing roles and permissions..."
python -c "from app import initialize_roles_permissions; initialize_roles_permissions()"

# Start the Flask app
echo "Starting Flask application..."
exec gunicorn --bind 0.0.0.0:$PORT app:app
