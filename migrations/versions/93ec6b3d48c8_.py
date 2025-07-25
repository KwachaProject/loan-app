"""empty message

Revision ID: 93ec6b3d48c8
Revises: 
Create Date: 2025-06-26 12:58:26.674189

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '93ec6b3d48c8'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('customers',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('national_id', sa.String(length=20), nullable=False),
    sa.Column('first_name', sa.String(length=100), nullable=False),
    sa.Column('last_name', sa.String(length=100), nullable=False),
    sa.Column('gender', sa.String(length=10), nullable=True),
    sa.Column('dob', sa.String(length=20), nullable=True),
    sa.Column('title', sa.String(length=20), nullable=True),
    sa.Column('email', sa.String(length=100), nullable=False),
    sa.Column('contact', sa.String(length=20), nullable=True),
    sa.Column('address', sa.String(length=255), nullable=True),
    sa.Column('next_of_kin_name', sa.String(length=20), nullable=False),
    sa.Column('next_of_kin_relationship', sa.String(length=20), nullable=False),
    sa.Column('next_of_kin_contact', sa.String(length=20), nullable=True),
    sa.Column('employer', sa.String(length=100), nullable=False),
    sa.Column('job_title', sa.String(length=100), nullable=True),
    sa.Column('salary', sa.Float(), nullable=True),
    sa.Column('service_length', sa.String(length=50), nullable=True),
    sa.Column('bank_name', sa.String(length=100), nullable=True),
    sa.Column('bank_account', sa.String(length=20), nullable=False),
    sa.Column('salary_deposited', sa.String(length=10), nullable=True),
    sa.Column('district', sa.String(length=100), nullable=True),
    sa.Column('region', sa.String(length=100), nullable=True),
    sa.Column('amount_requested', sa.Float(), nullable=True),
    sa.Column('status', sa.String(length=20), nullable=True),
    sa.Column('is_approved_for_creation', sa.Boolean(), nullable=True),
    sa.Column('maker_id', sa.Integer(), nullable=False),
    sa.Column('checker_id', sa.Integer(), nullable=True),
    sa.Column('is_approved_for_deletion', sa.Boolean(), nullable=True),
    sa.Column('file_number', sa.String(length=20), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=True),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('national_id')
    )
    op.create_table('cutoff_date_config',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('category', sa.String(length=50), nullable=False),
    sa.Column('cutoff_dt', sa.DateTime(), nullable=False),
    sa.Column('updated_at', sa.DateTime(), nullable=True),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('category')
    )
    op.create_table('permissions',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('resource', sa.String(length=50), nullable=True),
    sa.Column('action', sa.String(length=50), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('pricing_configs',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('category', sa.String(length=50), nullable=False),
    sa.Column('term_months', sa.Integer(), nullable=False),
    sa.Column('interest_rate', sa.Float(), nullable=False),
    sa.Column('origination_fee', sa.Float(), nullable=False),
    sa.Column('insurance_fee', sa.Float(), nullable=False),
    sa.Column('collection_fee', sa.Float(), nullable=False),
    sa.Column('crb_fee', sa.Float(), nullable=False),
    sa.Column('created_at', sa.DateTime(), nullable=True),
    sa.Column('updated_at', sa.DateTime(), nullable=True),
    sa.Column('apply_to_new', sa.Boolean(), nullable=True),
    sa.Column('apply_to_existing', sa.Boolean(), nullable=True),
    sa.Column('apply_interest_to_existing', sa.Boolean(), nullable=True),
    sa.Column('apply_collection_to_existing', sa.Boolean(), nullable=True),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('category', 'term_months', name='uq_category_term')
    )
    op.create_table('roles',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('name', sa.String(length=50), nullable=True),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('name')
    )
    op.create_table('votes',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('code', sa.String(length=10), nullable=False),
    sa.Column('description', sa.String(length=200), nullable=False),
    sa.Column('is_active', sa.Boolean(), nullable=True),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('code')
    )
    op.create_table('loan_applications',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('customer_id', sa.Integer(), nullable=False),
    sa.Column('loan_amount', sa.Float(), nullable=False),
    sa.Column('status', sa.String(length=20), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=True),
    sa.Column('term_months', sa.Integer(), nullable=True),
    sa.Column('monthly_instalment', sa.Float(), nullable=True),
    sa.Column('total_repayment', sa.Float(), nullable=True),
    sa.Column('effective_rate', sa.Float(), nullable=True),
    sa.Column('category', sa.String(length=50), nullable=True),
    sa.Column('loan_category', sa.Integer(), nullable=False),
    sa.Column('disbursed', sa.Boolean(), nullable=True),
    sa.Column('disbursed_bank', sa.String(length=100), nullable=True),
    sa.Column('crb_fees', sa.Float(), nullable=True),
    sa.Column('origination_fees', sa.Float(), nullable=True),
    sa.Column('insurance_fees', sa.Float(), nullable=True),
    sa.Column('total_fees', sa.Float(), nullable=True),
    sa.Column('collection_fees', sa.Float(), nullable=True),
    sa.Column('schedule_id', sa.Integer(), nullable=True),
    sa.Column('loan_number', sa.String(length=20), nullable=True),
    sa.Column('file_number', sa.String(length=50), nullable=True),
    sa.Column('date_created', sa.DateTime(), nullable=True),
    sa.Column('disbursement_date', sa.Date(), nullable=True),
    sa.Column('cash_to_client', sa.Float(), nullable=False),
    sa.Column('top_up_interest', sa.Float(), nullable=True),
    sa.Column('settlement_interest', sa.Float(), nullable=True),
    sa.Column('closure_type', sa.String(length=20), nullable=True),
    sa.Column('closure_date', sa.DateTime(), nullable=True),
    sa.Column('top_up_of', sa.Integer(), nullable=True),
    sa.Column('application_status', sa.String(length=20), nullable=False),
    sa.Column('loan_state', sa.String(length=20), nullable=False),
    sa.Column('performance_status', sa.String(length=20), nullable=False),
    sa.Column('top_up_balance', sa.Float(), nullable=True),
    sa.Column('settlement_balance', sa.Float(), nullable=True),
    sa.Column('current_balance', sa.Float(), nullable=True),
    sa.Column('settlement_type', sa.Enum('self_settlement', 'third_party', name='settlementtypeenum'), nullable=True),
    sa.Column('settling_institution', sa.String(length=255), nullable=True),
    sa.Column('settlement_reason', sa.String(length=255), nullable=True),
    sa.Column('vote_id', sa.Integer(), nullable=True),
    sa.Column('outstanding_fees', sa.Float(), nullable=True),
    sa.Column('pricing_version', sa.Integer(), nullable=True),
    sa.Column('applied_interest_rate', sa.Float(), nullable=True),
    sa.Column('applied_collection_fee', sa.Float(), nullable=True),
    sa.Column('parent_loan_id', sa.Integer(), nullable=True),
    sa.ForeignKeyConstraint(['customer_id'], ['customers.id'], ),
    sa.ForeignKeyConstraint(['parent_loan_id'], ['loan_applications.id'], ),
    sa.ForeignKeyConstraint(['schedule_id'], ['repayment_schedules.id'], name='fk_schedule_id', use_alter=True),
    sa.ForeignKeyConstraint(['top_up_of'], ['loan_applications.id'], ),
    sa.ForeignKeyConstraint(['vote_id'], ['votes.id'], ),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('loan_number')
    )
    op.create_table('role_permissions',
    sa.Column('role_id', sa.Integer(), nullable=True),
    sa.Column('permission_id', sa.Integer(), nullable=True),
    sa.ForeignKeyConstraint(['permission_id'], ['permissions.id'], ),
    sa.ForeignKeyConstraint(['role_id'], ['roles.id'], )
    )
    op.create_table('users',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('username', sa.String(length=100), nullable=True),
    sa.Column('password_hash', sa.String(length=512), nullable=False),
    sa.Column('email', sa.String(length=150), nullable=False),
    sa.Column('active', sa.Boolean(), nullable=False),
    sa.Column('role_id', sa.Integer(), nullable=True),
    sa.ForeignKeyConstraint(['role_id'], ['roles.id'], name='fk_users_role_id'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('email', name='uq_users_email'),
    sa.UniqueConstraint('username'),
    sa.UniqueConstraint('username', name='uq_users_username')
    )
    op.create_table('disbursements',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('loan_id', sa.Integer(), nullable=False),
    sa.Column('amount', sa.Float(), nullable=False),
    sa.Column('method', sa.String(length=20), nullable=True),
    sa.Column('status', sa.String(length=20), nullable=True),
    sa.Column('reference', sa.String(length=255), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=True),
    sa.ForeignKeyConstraint(['loan_id'], ['loan_applications.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('documents',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('customer_id', sa.Integer(), nullable=False),
    sa.Column('loan_id', sa.Integer(), nullable=True),
    sa.Column('filename', sa.String(length=255), nullable=False),
    sa.Column('filetype', sa.String(length=50), nullable=False),
    sa.Column('path', sa.String(length=512), nullable=False),
    sa.Column('uploaded_at', sa.DateTime(), nullable=True),
    sa.ForeignKeyConstraint(['customer_id'], ['customers.id'], ),
    sa.ForeignKeyConstraint(['loan_id'], ['loan_applications.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('journal_entries',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('date', sa.DateTime(), nullable=True),
    sa.Column('description', sa.String(length=200), nullable=True),
    sa.Column('amount', sa.Float(), nullable=True),
    sa.Column('entry_type', sa.String(length=50), nullable=True),
    sa.Column('gl_account', sa.String(length=50), nullable=True),
    sa.Column('user_id', sa.Integer(), nullable=True),
    sa.Column('loan_id', sa.Integer(), nullable=True),
    sa.ForeignKeyConstraint(['loan_id'], ['loan_applications.id'], ),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('loan_credits',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('loan_id', sa.Integer(), nullable=True),
    sa.Column('amount', sa.Float(), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=True),
    sa.Column('applied_at', sa.DateTime(), nullable=True),
    sa.Column('refunded_at', sa.DateTime(), nullable=True),
    sa.ForeignKeyConstraint(['loan_id'], ['loan_applications.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('notifications',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('recipient_id', sa.Integer(), nullable=True),
    sa.Column('message', sa.Text(), nullable=False),
    sa.Column('type', sa.String(length=50), nullable=True),
    sa.Column('is_read', sa.Boolean(), nullable=True),
    sa.Column('timestamp', sa.DateTime(), nullable=True),
    sa.ForeignKeyConstraint(['recipient_id'], ['users.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('payments',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('loan_id', sa.Integer(), nullable=False),
    sa.Column('amount', sa.Float(), nullable=False),
    sa.Column('reference', sa.String(length=100), nullable=True),
    sa.Column('method', sa.String(length=50), nullable=True),
    sa.Column('status', sa.String(length=20), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.Column('settlement_proof', sa.String(length=255), nullable=True),
    sa.ForeignKeyConstraint(['loan_id'], ['loan_applications.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('repayment_schedules',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('loan_id', sa.Integer(), nullable=True),
    sa.Column('instalment_no', sa.Integer(), nullable=True),
    sa.Column('due_date', sa.Date(), nullable=True),
    sa.Column('expected_amount', sa.Float(), nullable=True),
    sa.Column('expected_principal', sa.Float(), nullable=True),
    sa.Column('expected_interest', sa.Float(), nullable=True),
    sa.Column('expected_fees', sa.Float(), nullable=True),
    sa.Column('status', sa.String(length=20), nullable=True),
    sa.Column('paid_principal', sa.Float(), nullable=True),
    sa.Column('paid_interest', sa.Float(), nullable=True),
    sa.Column('paid_fees', sa.Float(), nullable=True),
    sa.Column('remaining_balance', sa.Float(), nullable=True),
    sa.Column('arrears_amount', sa.Float(), nullable=True),
    sa.ForeignKeyConstraint(['loan_id'], ['loan_applications.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('arrears',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('loan_id', sa.Integer(), nullable=False),
    sa.Column('schedule_id', sa.Integer(), nullable=True),
    sa.Column('due_date', sa.Date(), nullable=False),
    sa.Column('recorded_at', sa.DateTime(), nullable=False),
    sa.Column('expected_principal', sa.Float(), nullable=True),
    sa.Column('expected_interest', sa.Float(), nullable=True),
    sa.Column('expected_fees', sa.Float(), nullable=True),
    sa.Column('paid_principal', sa.Float(), nullable=True),
    sa.Column('paid_interest', sa.Float(), nullable=True),
    sa.Column('paid_fees', sa.Float(), nullable=True),
    sa.Column('payment_status', sa.String(length=20), nullable=True),
    sa.Column('status', sa.String(length=20), nullable=True),
    sa.ForeignKeyConstraint(['loan_id'], ['loan_applications.id'], ),
    sa.ForeignKeyConstraint(['schedule_id'], ['repayment_schedules.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('payment_allocations',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('payment_id', sa.Integer(), nullable=False),
    sa.Column('principal', sa.Float(), nullable=False),
    sa.Column('interest', sa.Float(), nullable=False),
    sa.Column('settlement_interest', sa.Float(), nullable=True),
    sa.Column('schedule_id', sa.Integer(), nullable=True),
    sa.Column('fees', sa.Float(), nullable=False),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['payment_id'], ['payments.id'], ),
    sa.ForeignKeyConstraint(['schedule_id'], ['repayment_schedules.id'], ),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('payment_id', name='uq_payment_allocation_payment_id')
    )
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('payment_allocations')
    op.drop_table('arrears')
    op.drop_table('repayment_schedules')
    op.drop_table('payments')
    op.drop_table('notifications')
    op.drop_table('loan_credits')
    op.drop_table('journal_entries')
    op.drop_table('documents')
    op.drop_table('disbursements')
    op.drop_table('users')
    op.drop_table('role_permissions')
    op.drop_table('loan_applications')
    op.drop_table('votes')
    op.drop_table('roles')
    op.drop_table('pricing_configs')
    op.drop_table('permissions')
    op.drop_table('cutoff_date_config')
    op.drop_table('customers')
    # ### end Alembic commands ###
