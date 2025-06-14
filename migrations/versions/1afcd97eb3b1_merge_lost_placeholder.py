"""merge lost placeholder

Revision ID: 1afcd97eb3b1
Revises: d32f895b2f28, 5589524b5c5a
Create Date: 2025-06-14 16:03:48.132536

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '1afcd97eb3b1'
down_revision = ('d32f895b2f28', '5589524b5c5a')
branch_labels = None
depends_on = None


def upgrade():
    pass


def downgrade():
    pass
