"""placeholder lost revision

Revision ID: 5589524b5c5a
Revises: c96f0881fe93
Create Date: 2025-06-14 12:56:00

"""
from alembic import op
import sqlalchemy as sa


# Revision identifiers, used by Alembic.
revision = '5589524b5c5a'
down_revision = 'c96f0881fe93'
branch_labels = None
depends_on = None


def upgrade():
    # Add your emergency columns here if not already handled manually
    with op.batch_alter_table("loan_applications") as batch_op:
        batch_op.add_column(sa.Column('current_balance', sa.Numeric(12, 2), nullable=True))
        batch_op.add_column(sa.Column('top_up_balance', sa.Numeric(12, 2), nullable=True))
        batch_op.add_column(sa.Column('settlement_balance', sa.Numeric(12, 2), nullable=True))
        batch_op.add_column(sa.Column('settlement_type', sa.String(length=50), nullable=True))
        batch_op.add_column(sa.Column('settling_institution', sa.String(length=255), nullable=True))
        batch_op.add_column(sa.Column('settlement_reason', sa.Text(), nullable=True))
        batch_op.add_column(sa.Column('parent_loan_id', sa.Integer(), nullable=True))


def downgrade():
    with op.batch_alter_table("loan_applications") as batch_op:
        batch_op.drop_column('parent_loan_id')
        batch_op.drop_column('settlement_reason')
        batch_op.drop_column('settling_institution')
        batch_op.drop_column('settlement_type')
        batch_op.drop_column('settlement_balance')
        batch_op.drop_column('top_up_balance')
        batch_op.drop_column('current_balance')
