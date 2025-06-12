#!/bin/bash

export FLASK_ENV=production
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

# Create the base migration placeholder if needed
if [ ! -f "migrations/versions/ea18c3ede092_placeholder.py" ]; then
    echo "Creating base migration placeholder..."
    cat > migrations/versions/ea18c3ede092_placeholder.py <<EOL
from alembic import op

revision = 'ea18c3ede092'
down_revision = None
branch_labels = None
depends_on = None

def upgrade():
    # Empty migration - safe placeholder
    pass

def downgrade():
    # Empty migration - safe placeholder
    pass
EOL
fi

# Create the missing migration placeholder if needed
if [ ! -f "migrations/versions/5589524b5c5a_placeholder.py" ]; then
    echo "Creating missing migration placeholder..."
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
fi

# Resolve multiple heads issue
echo "Resolving migration history..."
CURRENT_HEAD=$(flask db heads | grep -v '5589524b5c5a' | head -1 | awk '{print $1}')
if [ -n "$CURRENT_HEAD" ]; then
    echo "Merging migration heads..."
    flask db merge $CURRENT_HEAD 5589524b5c5a
fi

# Apply database upgrades
echo "Applying database upgrades..."
if flask db upgrade; then
    echo "Database upgrade successful"
else
    echo "Stamping database with head revision"
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