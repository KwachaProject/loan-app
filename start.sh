# Deployment start script 
#!/bin/bash

export FLASK_ENV=production
set -e  # Exit immediately if a command exits with a non-zero status.

echo "Starting deployment script..."

# Run database migrations using Alembic (via Flask-Migrate)
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

python -c "
import os
from app import db, create_app
from app import User

email = os.getenv('ADMIN_EMAIL')
password = os.getenv('ADMIN_PASSWORD')

if not email or not password:
    raise Exception('❌ ADMIN_EMAIL or ADMIN_PASSWORD environment variables not set.')

app = create_app()
with app.app_context():
    if not User.query.filter_by(email=email).first():
        admin = User(email=email, role='admin')
        admin.set_password(password)
        db.session.add(admin)
        db.session.commit()
        print(f'✅ Admin user created: {email}')
    else:
        print(f'ℹ️ Admin user already exists: {email}')
"

# Start the Flask app
echo "Starting Flask application..."
exec gunicorn --workers 4 --bind 0.0.0.0:$PORT app:app
