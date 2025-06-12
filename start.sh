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

# Special handling for your specific missing migration
echo "Applying database upgrades..."
if ! flask db upgrade; then
    if flask db upgrade 2>&1 | grep -q "Can't locate revision identified by '5589524b5c5a'"; then
        echo "⚠️  Detected missing migration chain - creating placeholders"
        
        # Create the first missing migration (ea18c3ede092)
        cat > migrations/versions/ea18c3ede092_placeholder.py <<EOL
from alembic import op

revision = 'ea18c3ede092'
down_revision = None  # Assume it's the base migration
branch_labels = None
depends_on = None

def upgrade():
    # Empty migration - safe placeholder
    pass

def downgrade():
    # Empty migration - safe placeholder
    pass
EOL

        # Create the second missing migration (5589524b5c5a)
        cat > migrations/versions/5589524b5c5a_placeholder.py <<EOL
from alembic import op

revision = '5589524b5c5a'
down_revision = 'ea18c3ede092'
branch_labels = None
depends_on = None

def upgrade():
    # Empty migration - safe placeholder
    pass

def downgrade():
    # Empty migration - safe placeholder
    pass
EOL

        echo "Created placeholder migration files"
        echo "Stamping database with revision 5589524b5c5a"
        flask db stamp 5589524b5c5a
        echo "Retrying database upgrade"
        flask db upgrade
    else
        echo "⚠️  General migration error detected. Trying head stamp..."
        flask db stamp head
        flask db upgrade
    fi
fi

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