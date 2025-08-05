"""Fix self-referencing agent model

Revision ID: 019afa9ba5a4
Revises: 7c33cdc8c277
Create Date: 2025-07-30 05:56:41.784139
"""

from alembic import op
import sqlalchemy as sa

# revision identifiers
revision = '019afa9ba5a4'
down_revision = '7c33cdc8c277'
branch_labels = None
depends_on = None

def upgrade():
    # Pre-fill missing roles using raw SQL (must come BEFORE batch_alter_table)
    op.execute("UPDATE agents SET role = 'Agent' WHERE role IS NULL")

    with op.batch_alter_table('agents', schema=None) as batch_op:
        batch_op.alter_column('district',
               existing_type=sa.VARCHAR(length=50),
               type_=sa.String(length=100),
               existing_nullable=True)
        batch_op.alter_column('region',
               existing_type=sa.VARCHAR(length=50),
               type_=sa.String(length=100),
               existing_nullable=True)
        batch_op.alter_column('role',
               existing_type=sa.VARCHAR(length=50),
               nullable=False)  # safe now
        batch_op.drop_column('active')


def downgrade():
    with op.batch_alter_table('agents', schema=None) as batch_op:
        batch_op.add_column(sa.Column('active', sa.BOOLEAN(), nullable=True))
        batch_op.alter_column('role',
               existing_type=sa.VARCHAR(length=50),
               nullable=True)
        batch_op.alter_column('region',
               existing_type=sa.String(length=100),
               type_=sa.VARCHAR(length=50),
               existing_nullable=True)
        batch_op.alter_column('district',
               existing_type=sa.String(length=100),
               type_=sa.VARCHAR(length=50),
               existing_nullable=True)
