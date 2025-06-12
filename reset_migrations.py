import os
from flask_migrate import Migrate
from app import app, db  # ⬅️ Import the existing app and db directly

# Initialize migrate with the already created app
migrate = Migrate(app, db)

def reset_migrations():
    # Backup existing migrations
    if os.path.exists('migrations'):
        os.system('rm -rf migrations_backup')
        os.system('mkdir migrations_backup')
        os.system('cp -r migrations/versions migrations_backup/')

    # Reset migrations
    os.system('rm -rf migrations')
    os.system('flask db init')
    os.system('flask db migrate -m "Reset migration history"')
    os.system('flask db stamp head')

    # Create marker file
    with open('.migration_reset_complete', 'w') as f:
        f.write('Migration reset completed')

    print("✅ Migration history reset complete")

if __name__ == '__main__':
    with app.app_context():
        reset_migrations()
