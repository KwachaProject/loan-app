import os
import sys
import logging
from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool

# Alembic Config object
config = context.config

# Setup logging
fileConfig(config.config_file_name)
logger = logging.getLogger('alembic.env')

# Override sqlalchemy.url from DATABASE_URL environment variable
database_url = os.getenv('DATABASE_URL')
if database_url:
    # Ensure correct scheme (Render often uses old "postgres://" format)
    if database_url.startswith("postgres://"):
        database_url = database_url.replace("postgres://", "postgresql://", 1)

    config.set_main_option('sqlalchemy.url', database_url)
    logger.info("Using DATABASE_URL from environment.")
else:
    logger.warning("DATABASE_URL not set. Falling back to alembic.ini config.")

# Add project root to path so app and db can be imported
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Import Flask app and db instance
from app import app, db

# Load target metadata within app context
with app.app_context():
    target_metadata = db.metadata
    logger.info(f"Connected to DB: {app.config['SQLALCHEMY_DATABASE_URI']}")
    logger.info(f"Metadata has {len(target_metadata.tables)} tables.")

def run_migrations_offline():
    """Run Alembic migrations in 'offline' mode."""
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()

def run_migrations_online():
    """Run Alembic migrations in 'online' mode."""
    connectable = engine_from_config(
        config.get_section(config.config_ini_section),
        prefix='sqlalchemy.',
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,
        )

        with context.begin_transaction():
            context.run_migrations()

# Run migrations based on mode
if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
