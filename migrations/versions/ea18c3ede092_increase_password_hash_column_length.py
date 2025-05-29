"""Increase password_hash column length

Revision ID: ea18c3ede092
Revises: b6ed7f37203a
Create Date: 2025-05-29 20:06:15.156358

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'ea18c3ede092'
down_revision = 'b6ed7f37203a'
branch_labels = None
depends_on = None


from alembic import op
import sqlalchemy as sa
from sqlalchemy.engine import reflection


def upgrade():
    bind = op.get_bind()
    if bind.dialect.name == 'sqlite':
        # SQLite workaround
        op.create_table(
            'users_tmp',
            sa.Column('id', sa.Integer, primary_key=True),
            sa.Column('username', sa.String(64), nullable=False),
            sa.Column('email', sa.String(120), nullable=False),
            sa.Column('password_hash', sa.String(512), nullable=False),
        )
        op.execute('INSERT INTO users_tmp (id, username, email, password_hash) SELECT id, username, email, password_hash FROM users')
        op.drop_table('users')
        op.rename_table('users_tmp', 'users')
    else:
        # Postgres (or others) can alter column directly
        op.alter_column('users', 'password_hash',
                        existing_type=sa.String(length=128),
                        type_=sa.String(length=512),
                        existing_nullable=False)


def downgrade():
    bind = op.get_bind()
    if bind.dialect.name == 'sqlite':
        op.create_table(
            'users_old',
            sa.Column('id', sa.Integer, primary_key=True),
            sa.Column('username', sa.String(64), nullable=False),
            sa.Column('email', sa.String(120), nullable=False),
            sa.Column('password_hash', sa.String(128), nullable=False),
        )
        op.execute('INSERT INTO users_old (id, username, email, password_hash) SELECT id, username, email, password_hash FROM users')
        op.drop_table('users')
        op.rename_table('users_old', 'users')
    else:
        op.alter_column('users', 'password_hash',
                        existing_type=sa.String(length=512),
                        type_=sa.String(length=128),
                        existing_nullable=False)
