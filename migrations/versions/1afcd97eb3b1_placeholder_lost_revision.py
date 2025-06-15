"""lost placeholder – no‑op

Revision ID: 1afcd97eb3b1
Revises: 5ada732a06fc   # <‑‑ the last *existing* revision in your repo
Create Date: 2025‑06‑15
"""

from alembic import op
import sqlalchemy as sa

# Revision identifiers, used by Alembic.
revision = '1afcd97eb3b1'
down_revision = '5ada732a06fc'   # make sure this file really exists
branch_labels = None
depends_on = None

def upgrade():
    pass

def downgrade():
    pass
