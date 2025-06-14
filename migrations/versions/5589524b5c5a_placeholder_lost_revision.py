"""placeholder for lost revision ea18c3ede092

Revision ID: 5589524b5c5a
Revises: c96f0881fe93
Create Date: 2025-06-14 12:00:00.000000

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '5589524b5c5a'
down_revision = 'c96f0881fe93'
branch_labels = None
depends_on = None


def upgrade():
    # this is a no-op placeholder, all schema was already applied manually
    pass


def downgrade():
    # nothing to undo
    pass
