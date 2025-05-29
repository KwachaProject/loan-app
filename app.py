from flask import Flask, render_template, request, redirect, url_for, flash, send_file, jsonify, abort 
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from sqlalchemy.exc import IntegrityError
from datetime import datetime
from io import BytesIO
from fpdf import FPDF
from datetime import datetime
from sqlalchemy import func
from sqlalchemy import event
import csv
import io
import os
from werkzeug.utils import secure_filename
import csv
from sqlalchemy.exc import IntegrityError
from flask import send_from_directory
from utils.file_upload import save_document
from datetime import datetime, timedelta
from dateutil.relativedelta import relativedelta
from sqlalchemy.orm.session import object_session
from sqlalchemy.ext.hybrid import hybrid_property
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Mail
from datetime import date
today = date.today()
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from sqlalchemy.exc import IntegrityError
import click
from flask import Flask
from sqlalchemy import func, extract
from sqlalchemy import Enum
import math
from typing import Dict, Union
import logging
from logging.handlers import RotatingFileHandler
import sys


log_dir = os.path.join(os.path.dirname(__file__), 'logs')
if not os.path.exists(log_dir):
    os.makedirs(log_dir)

# Initialize the Flask application
app = Flask(__name__)
app.secret_key = 'supersecretkey'
app.logger.setLevel(logging.INFO)

handler = RotatingFileHandler(
    'app.log',
    maxBytes=1024 * 1024,
    backupCount=5,
    encoding='utf-8'
)
handler.setFormatter(logging.Formatter(
    '[%(asctime)s] %(levelname)s in %(module)s: %(message)s'
))
app.logger.addHandler(handler)

log_handler = RotatingFileHandler('logs/loan_app.log', maxBytes=512000, backupCount=3)
log_handler.setLevel(logging.DEBUG)  # Capture all logs
formatter = logging.Formatter(
    '[%(asctime)s] %(levelname)s in %(module)s: %(message)s'
)
log_handler.setFormatter(formatter)
app.logger.addHandler(log_handler)
app.logger.setLevel(logging.DEBUG)

if os.name == 'nt':
    import ctypes
    ctypes.windll.kernel32.SetConsoleCP(65001)
    ctypes.windll.kernel32.SetConsoleOutputCP(65001)

if sys.stdout.encoding != 'UTF-8':
    sys.stdout.reconfigure(encoding='utf-8')
if sys.stderr.encoding != 'UTF-8':
    sys.stderr.reconfigure(encoding='utf-8')

console_handler = logging.StreamHandler()
console_handler.setLevel(logging.DEBUG)
console_handler.setFormatter(formatter)
app.logger.addHandler(console_handler)


@app.template_filter('money')
def money_format(value):
    try:
        return f"{float(value):,.2f}"
    except Exception:
        return "0.00"

@app.template_filter('time_ago')
def time_ago_filter(dt):
    if not isinstance(dt, datetime):
        return dt

    now = datetime.utcnow()
    delta = relativedelta(now, dt)

    if delta.years > 0:
        return f"{delta.years} year(s) ago"
    elif delta.months > 0:
        return f"{delta.months} month(s) ago"
    elif delta.days > 0:
        return f"{delta.days} day(s) ago"
    elif delta.hours > 0:
        return f"{delta.hours} hour(s) ago"
    elif delta.minutes > 0:
        return f"{delta.minutes} minute(s) ago"
    else:
        return "just now"

# Register the filter
app.jinja_env.filters['time_ago'] = time_ago_filter

import logging
from logging.handlers import RotatingFileHandler
import os
from flask import Flask

app = Flask(__name__)

# Configure logging
def setup_logging():
    # Create logger
    logger = logging.getLogger('LoanAppLogger')
    logger.setLevel(logging.INFO)

    # Create formatter
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s [%(pathname)s:%(lineno)d]'
    )




    # Rotating file handler
    log_file = os.path.join(log_dir, 'loan_app.log')
    file_handler = RotatingFileHandler(
        filename=log_file,
        maxBytes=512000,
        backupCount=3,
        encoding='utf-8'
    )
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    # Add console handler for development
    if app.debug:
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)

# Initialize logging
setup_logging()

@app.template_filter('datetimeformat')
def datetimeformat_filter(value, format='%Y-%m-%d %H:%M'):
    """Custom datetime format filter"""
    if value is None:
        return ""
    try:
        return value.strftime(format)
    except AttributeError:
        return ""

logging.basicConfig(
    filename='app.log',
    filemode='a',
    encoding='utf-8',  # <-- important
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
    )

# Determine the environment: "production" or "development"
db = SQLAlchemy()
migrate = Migrate()
mail = Mail()

# Create Flask app
app = Flask(__name__)

# Set environment
env = os.getenv("FLASK_ENV", "development")

# Use Postgres in production, SQLite locally
if env == "production":
    uri = os.getenv("DATABASE_URL")
    if uri and uri.startswith("postgres://"):
        uri = uri.replace("postgres://", "postgresql://", 1)
else:
    uri = "sqlite:///customers.db"

app.config['SQLALCHEMY_DATABASE_URI'] = uri
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
print("Connected to DB:", app.config['SQLALCHEMY_DATABASE_URI'])

# Email config (example: Gmail — replace with your own)
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'youremail@example.com'      # ✅ Replace!
app.config['MAIL_PASSWORD'] = 'your_app_password_here'     # ✅ Replace!
app.config['MAIL_DEFAULT_SENDER'] = 'youremail@example.com'

# File upload settings
app.config['UPLOAD_FOLDER'] = 'uploads/documents'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'pdf', 'doc', 'docx'}

# Security
app.config['SECRET_KEY'] = 'your-secret-key-123'  # ✅ Change this in production!

# Initialize extensions with app
db.init_app(app)
migrate.init_app(app, db)
mail.init_app(app)

login_manager = LoginManager(app)
# Import models after initializing the db instance
from app import db

UPLOAD_FOLDER = 'uploads/documents'
MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16 MB max upload size
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'pdf', 'doc', 'docx'}

import socket

@app.route("/server-info")
def server_info():
    db_uri = app.config['SQLALCHEMY_DATABASE_URI']
    env = os.getenv("FLASK_ENV", "development")
    return {
        "hostname": socket.gethostname(),
        "database_uri": db_uri,
        "environment": env
    }


PRICING = {
    3:  {'rate': 0.035, 'origination': 0.15,  'insurance': 0.008,  'collection': 0.0025,  'crb': 3000},
    6:  {'rate': 0.035, 'origination': 0.15,  'insurance': 0.014,  'collection': 0.0025,  'crb': 3000},
    9:  {'rate': 0.035, 'origination': 0.15,  'insurance': 0.02,   'collection': 0.015,   'crb': 3000},
    12: {'rate': 0.035, 'origination': 0.12,  'insurance': 0.026,  'collection': 0.01139, 'crb': 3000},
    15: {'rate': 0.035, 'origination': 0.2,   'insurance': 0.0297, 'collection': 0.01493, 'crb': 3000},
    18: {'rate': 0.035, 'origination': 0.2,   'insurance': 0.0358, 'collection': 0.014,   'crb': 3000},
    24: {'rate': 0.035, 'origination': 0.2,   'insurance': 0.037,  'collection': 0.0125,  'crb': 3000},
    36: {'rate': 0.035, 'origination': 0.3,   'insurance': 0.041,  'collection': 0.0112,  'crb': 3000},
    48: {'rate': 0.035, 'origination': 0.3,   'insurance': 0.045,  'collection': 0.0095,  'crb': 3000},
}

# ---------------- Models ----------------

from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

class User(db.Model, UserMixin):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True)  # ✅
    password_hash = db.Column(db.String(128), nullable=False)  # ✅
    email = db.Column(db.String(150), nullable=False)  # ✅
    active = db.Column(db.Boolean, default=True, nullable=False)  # ✅
    role_id = db.Column(db.Integer, db.ForeignKey('roles.id'), nullable=False)  # ✅
    role = db.relationship('Role')  # ✅ Relationship

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f'<User {self.username} - Role: {self.role.name}>'  # Access role.name

    __table_args__ = (
        db.UniqueConstraint('email', name='uq_users_email'),  # ✅ Now works
    )

class Role(db.Model):
    __tablename__ = 'roles'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True)
    permissions = db.relationship('Permission', secondary='role_permissions')

    def has_permission(self, resource, action):
        return db.session.query(Permission)\
            .join(role_permissions)\
            .filter(
                Permission.resource == resource,
                Permission.action == action,
                role_permissions.c.role_id == self.id
            )\
            .first() is not None


class Permission(db.Model):
    __tablename__ = 'permissions'
    id = db.Column(db.Integer, primary_key=True)
    resource = db.Column(db.String(50))  # e.g., 'customer', 'loan'
    action = db.Column(db.String(50))    # e.g., 'create', 'approve'

    
role_permissions = db.Table('role_permissions',
    db.Column('role_id', db.Integer, db.ForeignKey('roles.id')),
    db.Column('permission_id', db.Integer, db.ForeignKey('permissions.id'))
    )

from datetime import datetime
from app import db  # or wherever your SQLAlchemy instance is

class Notification(db.Model):
    __tablename__ = 'notifications'

    id = db.Column(db.Integer, primary_key=True)
    
    # Correct FK target → users.id, matching your User model
    recipient_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)  # Null = global
    recipient = db.relationship('User', backref='notifications')  # user.notifications access

    message = db.Column(db.Text, nullable=False)
    type = db.Column(db.String(50), default='info')  # Types: info, approval, warning, etc.
    is_read = db.Column(db.Boolean, default=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f'<Notification type={self.type}, to={self.recipient_id or "Admin"}>'

from functools import wraps
from flask import redirect, url_for, flash
from flask_login import current_user

def role_required(*roles):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            if not current_user.is_authenticated:
                flash("Please log in to access this page.", "warning")
                return redirect(url_for("login"))
            
            print(f"🔍 Current user: {current_user.username}, Role: {current_user.role.name}")
            
            if current_user.role.name not in roles:
                flash("You do not have permission to access this page.", "danger")
                return redirect(url_for("home"))
            
            return f(*args, **kwargs)
        return wrapper
    return decorator


login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class AccountingError(Exception):
    """Custom exception for accounting discrepancies"""
    def __init__(self, message="Accounting discrepancy detected"):
        self.message = message
        super().__init__(self.message)

class Customer(db.Model):
    __tablename__ = 'customers'

    id = db.Column(db.Integer, primary_key=True)
    national_id = db.Column(db.String(20), unique=True, nullable=False)
    first_name = db.Column(db.String(100), nullable=False)
    last_name = db.Column(db.String(100), nullable=False)
    gender = db.Column(db.String(10))
    dob = db.Column(db.String(20))
    title = db.Column(db.String(20))
    email = db.Column(db.String(100), nullable=False)
    contact = db.Column(db.String(20))
    address = db.Column(db.String(255))
    next_of_kin_name = db.Column(db.String(20),nullable=False)
    next_of_kin_relationship = db.Column(db.String(20),nullable=False)
    next_of_kin_contact = db.Column(db.String(20))
    employer = db.Column(db.String(100), nullable=False)
    job_title = db.Column(db.String(100))
    salary = db.Column(db.Float)
    service_length = db.Column(db.String(50))
    bank_name = db.Column(db.String(100))
    bank_account = db.Column(db.String(20), nullable=False)
    salary_deposited = db.Column(db.String(10))
    district = db.Column(db.String(100))
    region = db.Column(db.String(100))
    amount_requested = db.Column(db.Float)
    status = db.Column(db.String(20), default='pending')
    is_approved_for_creation = db.Column(db.Boolean, default=False)
    maker_id = db.Column(db.Integer, nullable=False)
    checker_id = db.Column(db.Integer)
    is_approved_for_deletion = db.Column(db.Boolean, default=False)
    file_number = db.Column(db.String(20))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


    loans = db.relationship('LoanApplication', back_populates='customer')
    
    def __repr__(self):
        return f'<Customer {self.first_name} {self.last_name}, Status: {self.status}>'

@property
def full_name(self):
        return f"{self.first_name} {self.last_name}"

class LoanApplication(db.Model):
    __tablename__ = 'loan_applications'

    id = db.Column(db.Integer, primary_key=True)
    customer_id = db.Column(db.Integer, db.ForeignKey('customers.id'), nullable=False)
    loan_amount = db.Column(db.Float,nullable=False, default=0.0)
    status = db.Column(db.String(20), default='pending')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    term_months = db.Column(db.Integer)
    monthly_instalment = db.Column(db.Float)
    total_repayment = db.Column(db.Float)
    effective_rate = db.Column(db.Float)
    category = db.Column(db.String(50))
    loan_category = db.Column(db.Integer, nullable=False)
    disbursed = db.Column(db.Boolean, default=False)
    disbursed_bank = db.Column(db.String(100))
    crb_fees = db.Column(db.Float, default=3000)
    origination_fees = db.Column(db.Float)
    insurance_fees = db.Column(db.Float)
    total_fees = db.Column(db.Float)
    collection_fees = db.Column(db.Float)
    schedule_id = db.Column(
    db.Integer,
    db.ForeignKey('repayment_schedules.id', use_alter=True, name='fk_schedule_id'),
    nullable=True
    )
    loan_number = db.Column(db.String(20), nullable=True, unique=True)
    file_number = db.Column(db.String(50))
    date_created = db.Column(db.DateTime, default=datetime.utcnow)
    disbursement_date = db.Column(db.Date, nullable=True)
    cash_to_client = db.Column(db.Float,nullable=False, default=0.0)
    top_up_interest = db.Column(db.Float, default=0.0)
    settlement_interest = db.Column(db.Float, default=0.0)
    closure_type = db.Column(db.String(20))  # 'settlement' or 'topup'
    closure_date = db.Column(db.DateTime) 
    top_up_of = db.Column(db.Integer, db.ForeignKey('loan_applications.id'), nullable=True)
    application_status = db.Column(db.String(20), nullable=False, default='pending')
    loan_state = db.Column(db.String(20), nullable=False, default='active')
    performance_status = db.Column(db.String(20), nullable=False, default='performing')
    top_up_balance = db.Column(db.Float, default=0.0)
    settlement_balance = db.Column(db.Float, default=0.0)
    
    
    parent_loan_id = db.Column(
        db.Integer, 
        db.ForeignKey('loan_applications.id'),
        nullable=True
    )


    topups = db.relationship(
        'LoanApplication',
        foreign_keys=[parent_loan_id],  # 👈 Specify which foreign key to use
        backref=db.backref('parent_loan', remote_side=[id]),
        cascade='all, delete-orphan'
    )

    payments = db.relationship('Payment', back_populates='loan', cascade='all, delete-orphan')
    customer = db.relationship('Customer', back_populates='loans') 
    repayment_schedules = db.relationship(
        'RepaymentSchedule',
        back_populates='loan',
        cascade='all, delete-orphan',
        foreign_keys='RepaymentSchedule.loan_id'
        )

    # In your LoanApplication model
    @property
    def is_topup(self):
        return self.parent_loan_id is not None

    def __repr__(self):
        return f'<LoanApplication for Customer ID {self.customer_id} - Status: {self.status}>'

    def generate_repayment_schedule(self):
        config = PRICING.get(self.term_months or 0, {})
        if not config:
            raise ValueError("No pricing config for loan term.")

        loan_amount = self.loan_amount or 0
        term = self.term_months or 0
        rate = config.get('rate', 0)

        # Fees (capitalized into loan)
        origination = loan_amount * config.get('origination', 0)
        insurance = loan_amount * config.get('insurance', 0)
        crb = config.get('crb', 0)
        capitalized = loan_amount + origination + insurance + crb

        # Monthly collection fee
        collection_fee = loan_amount * config.get('collection', 0)

        # Annuity (fixed monthly P+I)
        annuity_factor = (rate * (1 + rate) ** term) / ((1 + rate) ** term - 1)
        monthly_p_and_i = capitalized * annuity_factor

        # Start repayment from disbursement date
        start_date = self.disbursement_date or datetime.utcnow().date()
        remaining_principal = capitalized

        for i in range(1, term + 1):
            due_date = start_date + relativedelta(months=i)

            interest = remaining_principal * rate
            principal = monthly_p_and_i - interest

            if i == term:
                principal = remaining_principal
                monthly_p_and_i = principal + interest

            remaining_principal -= principal

            schedule = RepaymentSchedule(
                loan_id=self.id,
                due_date=due_date,
                expected_amount=round(monthly_p_and_i + collection_fee, 2),
                expected_principal=round(principal, 2),
                expected_interest=round(interest, 2),
                expected_fees=round(collection_fee, 2),
                status='due'
            )
            
    @property
    def balance(self):
        config = PRICING.get(self.term_months)
        if not config:
            return None

        capitalized = (
            self.loan_amount +
            (self.loan_amount * config.get('origination', 0)) +
            (self.loan_amount * config.get('insurance', 0)) +
            config.get('crb', 0)
        )

        paid_principal = sum(
            alloc.principal for p in self.payments if p.allocation for alloc in [p.allocation]
        )

        return round(capitalized - paid_principal, 2)

class Disbursement(db.Model):
    __tablename__ = 'disbursements'

    id = db.Column(db.Integer, primary_key=True)
    loan_id = db.Column(db.Integer, db.ForeignKey('loan_applications.id'), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    method = db.Column(db.String(20))  # e.g., 'bank', 'mpesa'
    status = db.Column(db.String(20), default='pending')  # 'pending', 'successful', etc.
    reference = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # This sets up the relationship properly
    loan = db.relationship('LoanApplication', backref='disbursements')
   
class RepaymentSchedule(db.Model):
        __tablename__ = 'repayment_schedules'
        id = db.Column(db.Integer, primary_key=True)
        loan_id = db.Column(db.Integer, db.ForeignKey('loan_applications.id'))
        due_date = db.Column(db.Date)
        expected_amount = db.Column(db.Float)
        expected_principal = db.Column(db.Float)
        expected_interest = db.Column(db.Float)
        expected_fees = db.Column(db.Float)
        status = db.Column(db.String(20))

        
        loan = db.relationship(
        "LoanApplication",
        back_populates="repayment_schedules",
        foreign_keys=[loan_id]
    )

class Payment(db.Model):
    __tablename__ = 'payments'
    
    id = db.Column(db.Integer, primary_key=True)
    loan_id = db.Column(db.Integer, db.ForeignKey('loan_applications.id'), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    reference = db.Column(db.String(100))
    method = db.Column(db.String(50))
    status = db.Column(db.String(20), default='pending')  
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    settlement_proof = db.Column(db.String(255)) 

    # Relationships
    loan = db.relationship('LoanApplication', back_populates='payments')
    allocation = db.relationship('PaymentAllocation', 
                               back_populates='payment', 
                               uselist=False, 
                               cascade='all, delete-orphan')


from sqlalchemy.orm.session import object_session

# or from wherever you define it

from sqlalchemy.orm.session import object_session
from sqlalchemy import event

@event.listens_for(Payment, 'after_insert')
def allocate_payment_listener(mapper, connection, target):
    session = object_session(target)
    if not session:
        raise RuntimeError("No active session found for payment allocation.")

    # Skip auto allocation for internal operations
    if target.method in ('internal_topup', 'internal_settlement'):
        app.logger.info(f"Skipping allocation for {target.method} payment ID {target.id}")
        return

    # Avoid duplicate allocations
    existing = session.query(PaymentAllocation).filter_by(payment_id=target.id).first()
    if existing:
        return

    # Fetch associated loan
    loan = session.query(LoanApplication).get(target.loan_id)
    if not loan:
        raise ValueError(f"Loan not found for payment ID {target.id} with loan_id {target.loan_id}")

    # Allocate payment as normal
    allocate_payment(target, loan)



def allocate_payment(payment: Payment, loan: LoanApplication):
    session = object_session(payment)
    if not session:
        raise RuntimeError("No active session for allocation")

    # Skip if already allocated
    if session.query(PaymentAllocation).filter_by(payment_id=payment.id).first():
        return

    config = PRICING.get(loan.term_months)
    if not config:
        raise ValueError(f"No pricing config for {loan.term_months} months")

    loan_amount = loan.loan_amount or 0
    capitalized = loan_amount + (loan_amount * config['origination']) + (loan_amount * config['insurance']) + config['crb']
    paid_principal = sum(p.allocation.principal for p in loan.payments if p.allocation and p.id != payment.id)
    remaining_principal = max(capitalized - paid_principal, 0)

    rate = config.get('rate', 0.0)
    interest = round(remaining_principal * rate, 2)
    method = (payment.method or '').lower()

    allocation = PaymentAllocation(payment_id=payment.id, principal=0.0, interest=0.0, fees=0.0)

    if method in ('internal_topup', 'internal_settlement'):
        # Internal settlement: no fees, allocate to principal + capture interest to special fields
        interest = min(interest, payment.amount)
        principal = round(payment.amount - interest, 2)

        # Cap principal
        principal = min(principal, remaining_principal)

        allocation.principal = principal
        allocation.interest = 0.0
        allocation.fees = 0.0

        if loan.closure_type == 'topup':
            loan.top_up_interest = interest
        elif loan.closure_type == 'settlement':
            loan.settlement_interest = interest

    else:
        # Normal repayment
        collection_fee = round(loan_amount * config['collection'], 2)
        fees = min(collection_fee, payment.amount)
        remaining = payment.amount - fees

        interest = min(interest, remaining)
        principal = max(remaining - interest, 0)
        principal = min(principal, remaining_principal)

        allocation.principal = round(principal, 2)
        allocation.interest = round(interest, 2)
        allocation.fees = round(fees, 2)

    session.add(allocation)
    session.add(loan)


class PaymentAllocation(db.Model):
    __tablename__ = 'payment_allocations'

    id = db.Column(db.Integer, primary_key=True)
    payment_id = db.Column(db.Integer, db.ForeignKey('payments.id'), nullable=False)
    principal = db.Column(db.Float, nullable=False)
    interest = db.Column(db.Float, nullable=False)
    fees = db.Column(db.Float, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    # Enforce one allocation per payment
    __table_args__ = (
        db.UniqueConstraint('payment_id', name='uq_payment_allocation_payment_id'),
    )

    # Relationship
    payment = db.relationship('Payment', back_populates='allocation')

class JournalEntry(db.Model):
    __tablename__ = 'journal_entries'
    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.DateTime, default=datetime.utcnow)
    description = db.Column(db.String(200))
    amount = db.Column(db.Float)  # Positive for income, negative for assets
    entry_type = db.Column(db.String(50))  # principal_recovery/interest_income
    gl_account = db.Column(db.String(50))  # GL account code
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    loan_id = db.Column(db.Integer, db.ForeignKey('loan_applications.id'))
    
    user = db.relationship('User')
    loan = db.relationship('LoanApplication')

class Document(db.Model):
    __tablename__ = 'documents'
    id = db.Column(db.Integer, primary_key=True)
    customer_id = db.Column(db.Integer, db.ForeignKey('customers.id'), nullable=False)
    loan_id = db.Column(db.Integer, db.ForeignKey('loan_applications.id'))  # Optional for loan-specific docs
    filename = db.Column(db.String(255), nullable=False)
    filetype = db.Column(db.String(50), nullable=False)  # 'id_front', 'id_back', 'photo', 'payslip', etc.
    path = db.Column(db.String(512), nullable=False)
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Relationships
    customer = db.relationship('Customer', backref=db.backref('documents', lazy=True))
    loan = db.relationship('LoanApplication', backref=db.backref('documents', lazy=True))


# In LoanApplication model
def create_loan(requested_amount, term_months):
    try:
        requested_amount = float(request.form.get('requested_amount'))
        if requested_amount <= 0:
            raise ValueError("Amount must be positive")
    except (ValueError, TypeError):
        flash("Invalid requested amount", "danger")
        return redirect(url_for('loan_application_form'))

    # Get pricing config
    term_months = int(request.form.get('term_months'))
    config = PRICING.get(term_months)
    if not config:
        flash("Invalid loan term", "danger")
        return redirect(url_for('loan_application_form'))

    # Calculate fees
    orig_fee = requested_amount * config['origination']
    ins_fee = requested_amount * config['insurance']
    crb_fee = config['crb']

    # Calculate total loan amount (capitalized)
    capitalized_fees = orig_fee + ins_fee + crb_fee
    loan_amount = requested_amount + capitalized_fees

    # Create loan with validated values
    loan = LoanApplication(
        requested_amount=round(requested_amount, 2),
        loan_amount=round(loan_amount, 2),
        term_months=term_months,
        outstanding_balance=round(loan_amount, 2),  # Initial balance = full loan amount
        crb_fees=round(crb_fee, 2),
        origination_fees=round(orig_fee, 2),
        insurance_fees=round(ins_fee, 2),
        # ... other required fields ...
    )

    db.session.add(loan)
    db.session.commit()

    disbursement = Disbursement(
    loan_id=loan.id,
    amount=requested_amount,
    method='bank',
    status='pending',
    reference=f"Initial disbursement for {loan.loan_number}"
    )
    db.session.add(disbursement)
    db.session.commit()

    return loan

from sqlalchemy.orm import configure_mappers
configure_mappers()

def create_roles_and_permissions():
    # Create roles
    roles = ['admin', 'loan_officer', 'customer_support']
    for role_name in roles:
        if not Role.query.filter_by(name=role_name).first():
            role = Role(name=role_name)
            db.session.add(role)
    
    # Create permissions (example)
    permissions = [
        ('customer', 'create'),
        ('loan', 'approve'),
    ]
    for resource, action in permissions:
        if not Permission.query.filter_by(resource=resource, action=action).first():
            perm = Permission(resource=resource, action=action)
            db.session.add(perm)
    
    db.session.commit()

@app.cli.command("create-admin")
def create_admin():
    """Create admin user"""
    admin_role = Role.query.filter_by(name='admin').first()
    if not admin_role:
        print("Admin role not found! Run 'flask init-rbac' first")
        return

    if not User.query.filter_by(username='admin').first():
        admin = User(
            username='admin',
            email='admin@example.com',
            role=admin_role,
            active=True
        )
        admin.set_password('admin123')
        db.session.add(admin)
        db.session.commit()
        print("Admin user created with password 'admin123'")
    else:
        print("Admin user already exists")

    
@property
def full_name(self):
        return f"{self.first_name} {self.last_name}"

@property
def total_paid(self):
    return sum(payment.amount for payment in self.payments)

@property
def balance(self):
    return (self.loan_amount or 0) - self.total_paid

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Function to save documents
def save_document(file, customer_id, document_type):
    if file and allowed_file(file.filename):
        # Create unique filename
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        ext = file.filename.rsplit('.', 1)[1].lower()
        filename = f"{customer_id}_{document_type}_{timestamp}.{ext}"
        filename = secure_filename(filename)
        
        # Ensure upload directory exists
        os.makedirs(UPLOAD_FOLDER, exist_ok=True)
        filepath = os.path.join(UPLOAD_FOLDER, filename)
        
        # Save file
        file.save(filepath)
        return filename, filepath
    return None, None

def send_notification(message, type='info', recipient_id=None):
    notification = Notification(
        message=message,
        type=type,
        recipient_id=recipient_id
    )
    db.session.add(notification)
    db.session.commit()


@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    if current_user.role.name != 'admin':
        abort(403)

    users = User.query.all()
    roles = Role.query.all()
    section = request.args.get('section', 'users')  # Default to 'users' tab
    return render_template('admin_dashboard.html', users=users, roles=roles, section=section)

# Route to view a document
from flask_mail import Message
# Add to app.py
@app.route('/admin/permissions')
@role_required("admin")
def admin_permissions():
    roles = Role.query.all()
    pages = ['customer', 'loan', 'disbursement', 'payment', 'loanbook', 'admin']
    actions = ['create', 'approve', 'edit', 'delete', 'view']
    return render_template('admin_dashboard.html', section='permissions',
                           roles=roles, pages=pages, actions=actions)

@app.route('/update_permissions', methods=['POST'])
@role_required("admin")
def update_permissions():
    roles = Role.query.all()
    pages = ['customer', 'loan', 'disbursement', 'payment', 'loanbook', 'admin']
    actions = ['create', 'approve', 'edit', 'delete', 'view']

    for role in roles:
        for page in pages:
            for action in actions:
                perm_name = f'perm_{role.id}_{page}_{action}'
                permission = Permission.query.filter_by(resource=page, action=action).first()
                if not permission:
                    continue
                if perm_name in request.form:
                    if permission not in role.permissions:
                        role.permissions.append(permission)
                else:
                    if permission in role.permissions:
                        role.permissions.remove(permission)
    db.session.commit()
    flash('Permissions updated successfully', 'success')
    return redirect(url_for('admin_permissions'))


def permission_required(resource, action):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.role.has_permission(resource, action):
                abort(403)
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def create_initial_roles():
    roles = [
        ('admin', 'Full access'),
        ('credit_officer', 'Credit operations'),
        ('finance_officer', 'Financial management'),
        ('sales_ops', 'Sales operations'),
        ('chief_operations', 'Operations management'),
        ('chief_finance', 'Financial oversight'),
        ('chief_executive', 'Executive oversight')
    ]
    
    actions = ['create', 'view', 'edit', 'delete', 'approve']
    resources = ['customer', 'loan', 'disbursement', 'payment', 'loanbook', 'admin']

    # Create permissions
    for resource in resources:
        for action in actions:
            if not Permission.query.filter_by(resource=resource, action=action).first():
                perm = Permission(resource=resource, action=action)
                db.session.add(perm)

    # Create roles with default permissions
    for role_name, description in roles:
        role = Role.query.filter_by(name=role_name).first()
        if not role:
            role = Role(name=role_name)
            db.session.add(role)
            
            # Assign default permissions
            if role_name == 'admin':
                perms = Permission.query.all()
            else:
                perms = Permission.query.filter(Permission.action == 'view').all()
                
            role.permissions.extend(perms)

    db.session.commit()

# Add to manage_users route context
# ---------- Users Tab ----------
@app.route('/admin/users')
@role_required("admin")
def admin_users():
    users = User.query.all()
    roles = Role.query.all()
    pages = ['customer', 'loan', 'disbursement', 'payment', 'loanbook', 'admin']
    actions = ['create', 'approve', 'edit', 'delete', 'view']
    return render_template('admin_dashboard.html', section='users',
                           users=users, roles=roles, pages=pages, actions=actions)


@app.route('/create_user', methods=['POST'])
@role_required("admin")
def create_user():
    username = request.form.get('username')
    email = request.form.get('email')
    password = request.form.get('password')
    role_id = request.form.get('role_id')

    if not all([username, email, password, role_id]):
        flash('All fields are required', 'danger')
        return redirect(url_for('admin_users'))

    if User.query.filter((User.username == username) | (User.email == email)).first():
        flash('Username or email already exists', 'danger')
        return redirect(url_for('admin_users'))

    user = User(username=username, email=email, role_id=role_id, active=True)
    user.set_password(password)

    db.session.add(user)
    db.session.commit()
    flash('User created successfully', 'success')
    return redirect(url_for('admin_users'))


@app.route('/update_user_role', methods=['POST'])
@role_required("admin")
def update_user_role():
    user_id = request.form.get('user_id')
    new_role = request.form.get('role')
    user = User.query.get(user_id)
    if user:
        user.role_id = new_role
        db.session.commit()
        flash(f"{user.username}'s role updated", "success")
    return redirect(url_for('admin_users'))


@app.route('/toggle_user_status', methods=['POST'])
@role_required("admin")
def toggle_user_status():
    user_id = request.form.get('user_id')
    user = User.query.get(user_id)
    if user:
        user.active = not user.active
        db.session.commit()
        flash(f"{user.username} is now {'active' if user.active else 'inactive'}", "info")
    return redirect(url_for('admin_users'))


@app.route('/delete_user', methods=['POST'])
@role_required("admin")
def delete_user():
    user_id = request.form.get('user_id')
    user = User.query.get(user_id)
    if user:
        db.session.delete(user)
        db.session.commit()
        flash(f"User {user.username} deleted", "danger")
    return redirect(url_for('admin_users'))

from datetime import datetime
from sqlalchemy import func, extract

from flask_login import current_user
from sqlalchemy import and_

@app.route('/admin/notifications')
@login_required
@role_required('admin')
def admin_notifications():
    # Create disbursement-related notifications
    duplicate_disbursements = (
        db.session.query(
            Customer.national_id,
            Customer.file_number,
            func.count(LoanApplication.id).label('disbursed_count')
        )
        .join(LoanApplication, LoanApplication.customer_id == Customer.id)
        .filter(LoanApplication.disbursement_date != None)
        .group_by(Customer.national_id, Customer.file_number)
        .having(func.count(LoanApplication.id) > 1)
        .all()
    )

    for nd in duplicate_disbursements:
        msg = f"Disbursement made more than once for National ID: {nd.national_id} / File Number: {nd.file_number} ({nd.disbursed_count} times)"
        exists = Notification.query.filter_by(message=msg).first()
        if not exists:
            db.session.add(Notification(message=msg, recipient_id=None, type='warning'))  # Global to all admins

    # Create duplicate payment notifications
    duplicate_payments = (
        db.session.query(
            LoanApplication.loan_number,
            extract('year', Payment.created_at).label('year'),
            extract('month', Payment.created_at).label('month'),
            func.count(Payment.id).label('payment_count')
        )
        .join(Payment, Payment.loan_id == LoanApplication.id)
        .group_by(LoanApplication.loan_number, 'year', 'month')
        .having(func.count(Payment.id) > 1)
        .all()
    )

    for np in duplicate_payments:
        msg = f"Payment processed more than once for Loan Number: {np.loan_number} in {int(np.month)}/{int(np.year)} ({np.payment_count} times)"
        exists = Notification.query.filter_by(message=msg).first()
        if not exists:
            db.session.add(Notification(message=msg, recipient_id=None, type='warning'))

    db.session.commit()

    # Show global (recipient_id is NULL) + admin's own notifications (if needed)
    notifications = Notification.query.filter(
        Notification.recipient_id == None  # Only global
    ).order_by(Notification.timestamp.desc()).all()

    notifications = Notification.query.filter_by(recipient_id=None).order_by(Notification.timestamp.desc()).all()
    unread_count = Notification.query.filter_by(recipient_id=None, is_read=False).count()

    return render_template(
    'admin_dashboard.html',
    section='notifications',
    notifications=notifications,
    unread_count=unread_count
    )

@app.route('/admin/notifications/mark_read/<int:notification_id>')
@login_required
@role_required('admin')
def mark_notification_read(notification_id):
    notification = Notification.query.get_or_404(notification_id)

    if notification.recipient_id is not None:
        # Optional: ensure the right user is reading it
        abort(403)

    if not notification.is_read:
        notification.is_read = True
        db.session.commit()

    return redirect(url_for('admin_notifications'))


@app.route('/admin/reports')
@role_required("admin")
def admin_reports():
    return render_template('admin_dashboard.html', section='reports')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            if not user.active:
                flash('This account is deactivated', 'danger')
                return redirect(url_for('login'))
            login_user(user)
            return redirect(url_for('home'))
        flash('Invalid username or password', 'danger')
    return render_template('login.html')

def notify_ceo_loan_approved(customer_name, loan_amount):
    ceo = User.query.filter_by(role='ceo').first()
    if ceo:
        msg = Message("Loan Ready for CEO Approval", recipients=[ceo.email])
        msg.body = f"The loan for customer {customer_name} (amount: {loan_amount}) has been approved by the CFO and awaits your review."
        mail.send(msg)

@app.cli.command("init-rbac")
def init_rbac():
    """Initialize roles and permissions"""
    roles = [
        ('admin', 'Full access'),
        ('credit_officer', 'Credit operations'),
        ('finance_officer', 'Financial management'),
        ('sales_ops', 'Sales operations'),
        ('chief_operations', 'Operations management'),
        ('chief_finance', 'Financial oversight'),
        ('chief_executive', 'Executive oversight')
    ]
    
    # Create roles
    for name, description in roles:
        if not Role.query.filter_by(name=name).first():
            role = Role(name=name)
            db.session.add(role)
    
    # Create permissions
    resources = ['customer', 'loan', 'disbursement', 'payment', 'loanbook', 'admin']
    actions = ['create', 'view', 'edit', 'delete', 'approve']
    
    for resource in resources:
        for action in actions:
            if not Permission.query.filter_by(resource=resource, action=action).first():
                perm = Permission(resource=resource, action=action)
                db.session.add(perm)
    
    # Assign all permissions to admin
    admin_role = Role.query.filter_by(name='admin').first()
    admin_role.permissions = Permission.query.all()
    
    db.session.commit()
    print("RBAC system initialized")

from sqlalchemy.orm import joinedload


from sqlalchemy.orm import joinedload

def calculate_annuity_payment(capitalized_amount: float, term: int, rate: float) -> float:
    """Calculate fixed monthly annuity payment with safety checks."""
    try:
        if term <= 0 or rate <= 0 or capitalized_amount <= 0:
            return 0.0
            
        # Handle potential overflow in exponential calculations
        factor_numerator = rate * (1 + rate) ** term
        factor_denominator = (1 + rate) ** term - 1
        
        # Prevent division by zero
        if factor_denominator < 1e-9:  # Near-zero check
            return capitalized_amount / term  # Fallback to simple division
            
        return (capitalized_amount * factor_numerator) / factor_denominator
    except (TypeError, ValueError, OverflowError):
        return 0.0

def calculate_capitalized_amount(loan_amount: float, config: dict) -> float:
            """Calculate capitalized amount from fees + CRB"""
            try:
                origination_fee = loan_amount * config.get('origination', 0)
                insurance_fee = loan_amount * config.get('insurance', 0)
                crb_fee = config.get('crb', 0)
                return round(loan_amount + origination_fee + insurance_fee + crb_fee, 2)
            except Exception as e:
                print(f"Capitalized amount error: {e}")
                return loan_amount

from datetime import datetime

def calculate_balances(loan) -> Dict[str, Union[float, datetime]]:
    """
    Calculate loan balances with proper type handling and validation
    Returns dictionary with all balance values even on error
    """
    DEFAULT_BALANCES = {
        'capitalized_amount': 0.0,
        'current_balance': 0.0,
        'top_up_balance': 0.0,
        'settlement_balance': 0.0,
        'top_up_interest': 0.0,
        'settlement_interest': 0.0,
        'closure_date': datetime.utcnow()
    }

    try:
        # Validate loan object
        if not loan or not hasattr(loan, 'term_months') or not hasattr(loan, 'payments'):
            raise ValueError("Invalid loan object structure")

        # Get pricing config with fallback
        config = PRICING.get(loan.term_months) or {}
        loan_amount = getattr(loan, 'loan_amount', 0.0)

        # Validate essential parameters
        if not all([
            isinstance(loan.term_months, int),
            loan.term_months > 0,
            loan_amount > 0,
            isinstance(config, dict)
        ]):
            return DEFAULT_BALANCES

        # Calculate capitalized amount with validation
        capitalized_amount = calculate_capitalized_amount(loan_amount, config)
        if not isinstance(capitalized_amount, (int, float)):
            capitalized_amount = loan_amount  # Fallback to original amount

        # Core calculations
        monthly_rate = config.get('rate', 0.0)
        annuity = calculate_annuity_payment(
            capitalized_amount, 
            loan.term_months, 
            monthly_rate
        )

        # Payment processing with type checks
        running_balance = float(capitalized_amount)
        payments_made = 0
        total_paid = 0.0

        for payment in sorted(loan.payments, key=lambda p: getattr(p, 'created_at', datetime.min)):
            if getattr(payment, 'status', '') == 'successful':
                total_paid += float(getattr(payment, 'amount', 0.0))

            allocation = getattr(payment, 'allocation', None)
            if allocation and getattr(allocation, 'principal', 0) > 0:
                running_balance -= float(allocation.principal)
                payments_made += 1
                running_balance = max(running_balance, 0.0)

        current_balance = round(float(max(running_balance, 0.0)), 2)
        remaining_term = max(int(loan.term_months) - payments_made, 0)

        # Interest calculations with fallbacks
        created_date = getattr(loan, 'date_created', datetime.utcnow())
        months_elapsed = max((datetime.utcnow() - created_date).days // 30, 0)
        accrued_interest = monthly_rate * loan_amount * months_elapsed
        
        # Projected interest calculation
        def safe_projected_interest(months: int) -> float:
            try:
                temp_balance = current_balance
                total_interest = 0.0
                monthly_rate_decimal = monthly_rate / 100 if monthly_rate > 1 else monthly_rate
                
                for _ in range(min(months, remaining_term)):
                    if temp_balance <= 0:
                        break
                    interest = temp_balance * monthly_rate_decimal
                    total_interest += interest
                    temp_balance -= (annuity - interest)
                
                return round(float(total_interest), 2)
            except:
                return 0.0

        next_3_interest = safe_projected_interest(3)
        next_6_interest = safe_projected_interest(6)

        return {
            'capitalized_amount': round(float(capitalized_amount), 2),
            'current_balance': current_balance,
            'top_up_balance': round(current_balance + next_3_interest, 2),
            'settlement_balance': round(current_balance + next_6_interest, 2),
            'top_up_interest': next_3_interest,
            'settlement_interest': next_6_interest,
            'closure_date': datetime.utcnow()
        }

    except Exception as e:
        # Use proper logging in production
        print(f"Balance calculation error: {str(e)}")
        return DEFAULT_BALANCES

from flask import render_template, request, redirect, url_for, flash
from flask_login import login_required
from sqlalchemy.orm import joinedload
from datetime import datetime

@app.route('/customer/<file_number>/account')
@login_required
@role_required('admin')
def customer_account(file_number: str):
    try:
        customer = Customer.query.filter_by(file_number=file_number).first_or_404()

        loans = (
            LoanApplication.query
            .options(joinedload(LoanApplication.payments))
            .filter(LoanApplication.customer_id == customer.id)
            .all()
        )
        app.logger.info(f"Found {len(loans)} loans for customer {file_number}")
        app.logger.info(f"Customer ID: {customer.id}")
        app.logger.info(f"Found Loans: {[(loan.loan_number, loan.loan_state) for loan in loans]}")
        
        def calculate_capitalized_amount(loan_amount: float, config: dict) -> float:
            try:
                origination = loan_amount * config.get('origination', 0)
                insurance = loan_amount * config.get('insurance', 0)
                crb = config.get('crb', 0)
                return round(loan_amount + origination + insurance + crb, 2)
            except Exception as e:
                app.logger.warning(f"Capitalization error: {e}")
                return loan_amount

        def calculate_balances(loan):
            config = PRICING.get(loan.term_months, {})
            if not config:
                return {}

            capitalized = calculate_capitalized_amount(loan.loan_amount or 0, config)
            monthly_rate = config.get('rate', 0)
            term = loan.term_months or 0

            if monthly_rate > 0 and term > 0:
                factor = (monthly_rate * (1 + monthly_rate) ** term) / ((1 + monthly_rate) ** term - 1)
                annuity = capitalized * factor
            else:
                annuity = 0

            payments = sorted(loan.payments, key=lambda p: p.created_at)
            remaining_balance = capitalized
            payments_made = 0

            for p in payments:
                if p.allocation and p.allocation.principal:
                    remaining_balance -= p.allocation.principal
                    remaining_balance = max(remaining_balance, 0)
                    payments_made += 1

            current_balance = round(remaining_balance, 2)
            remaining_term = max(term - payments_made, 0)

            def projected_interest(months_ahead):
                temp_balance = current_balance
                total_interest = 0.0
                for _ in range(min(months_ahead, remaining_term)):
                    if temp_balance <= 0:
                        break
                    interest = temp_balance * monthly_rate
                    principal = annuity - interest
                    principal = min(principal, temp_balance)
                    total_interest += interest
                    temp_balance -= principal
                return round(total_interest, 2)

            return {
                'capitalized_amount': capitalized,
                'current_balance': current_balance,
                'top_up_balance': round(current_balance + projected_interest(3), 2),
                'settlement_balance': round(current_balance + projected_interest(6), 2),
                'top_up_interest': projected_interest(3),
                'settlement_interest': projected_interest(6),
            }

        for loan in loans:
            balances = calculate_balances(loan)
            loan.capitalized_amount = balances.get('capitalized_amount', 0.0)
            loan.current_balance = balances.get('current_balance', 0.0)
            loan.top_up_balance = balances.get('top_up_balance', 0.0)
            loan.settlement_balance = balances.get('settlement_balance', 0.0)
            loan.top_up_interest = balances.get('top_up_interest', 0.0)
            loan.settlement_interest = balances.get('settlement_interest', 0.0)

            if loan.loan_state == 'active':
                loan.cash_to_client = round(loan.loan_amount - loan.top_up_balance, 2)
            else:
                loan.cash_to_client = loan.loan_amount

        return render_template(
            'customer_account.html',
            customer=customer,
            loans=loans,
            section=request.args.get('section', 'statement')
        )

    except Exception as e:
        app.logger.error(f"Account view error: {str(e)}")
        flash("Error loading account details", "danger")
        return redirect(url_for('home'))


@app.route('/loan/<loan_number>/statement')
def loan_statement(loan_number):
    try:
        loan = (LoanApplication.query
                .options(
                    db.joinedload(LoanApplication.customer),
                    db.joinedload(LoanApplication.payments)
                        .joinedload(Payment.allocation)
                )
                .filter_by(loan_number=loan_number)
                .first_or_404())
        
        config = PRICING.get(loan.term_months or 0, {})
        loan_amount = loan.loan_amount or 0
        capitalized_amount = (
            loan_amount +
            (loan_amount * config.get('origination', 0)) +
            (loan_amount * config.get('insurance', 0)) +
            config.get('crb', 0)
        )
        
        running_balance = capitalized_amount
        payments_made = 0
        for payment in sorted(loan.payments, key=lambda p: p.created_at):
            if payment.allocation and payment.allocation.principal:
                running_balance -= payment.allocation.principal
                payments_made += 1
        current_balance = max(round(running_balance, 2), 0.00)
        
        monthly_rate = config.get('rate', 0)
        term = loan.term_months
        remaining_term = term - payments_made
        
        if monthly_rate > 0 and term > 0:
            annuity_factor = (monthly_rate * (1 + monthly_rate) ** term) / ((1 + monthly_rate) ** term - 1)
            annuity_payment = capitalized_amount * annuity_factor
        else:
            annuity_payment = 0
        
        def calculate_projected_interest(months_ahead):
            temp_balance = current_balance
            total_interest = 0.0
            for _ in range(min(months_ahead, remaining_term)):
                if temp_balance <= 0:
                    break
                interest = temp_balance * monthly_rate
                principal = annuity_payment - interest
                principal = min(principal, temp_balance)
                total_interest += interest
                temp_balance -= principal
            return total_interest
        
        top_up_balance = round(current_balance + calculate_projected_interest(3), 2)
        settlement_balance = round(current_balance + calculate_projected_interest(6), 2)
        
        statement = []
        running_balance_display = capitalized_amount
        for payment in sorted(loan.payments, key=lambda p: p.created_at):
            if not payment.allocation:
                continue
            allocation = payment.allocation
            running_balance_display -= allocation.principal
            allocated_total = (allocation.principal or 0) + (allocation.interest or 0) + (allocation.fees or 0)
            valid_allocation = abs(allocated_total - payment.amount) < 0.01
            statement.append({
                'date': payment.created_at.strftime('%Y-%m-%d'),
                'total': payment.amount,
                'principal': allocation.principal,
                'interest': allocation.interest,
                'collection_fees': allocation.fees,
                'remaining_balance': round(running_balance_display, 2),
                'method': payment.method,
                'reference': payment.reference,
                'valid_allocation': valid_allocation
            })
        
        totals = {
            'paid': sum(p.amount for p in loan.payments),
            'principal': sum(p.allocation.principal for p in loan.payments if p.allocation),
            'interest': sum(p.allocation.interest for p in loan.payments if p.allocation),
            'fees': sum(p.allocation.fees for p in loan.payments if p.allocation)
        }
        
        print(f"current_balance={current_balance}, top_up_balance={top_up_balance}, settlement_balance={settlement_balance}")
        return render_template(
            'loan_statement.html',
            loan=loan,
            loan_state=loan.loan_state,
            statement=statement,
            capitalized_amount=round(capitalized_amount, 2),
            current_balance=current_balance,
            top_up_balance=top_up_balance,
            settlement_balance=settlement_balance,
            totals=totals
        )
    except Exception as e:
        flash(f"Error generating statement: {str(e)}", "danger")
        return redirect(url_for('loanbook'))
        
    except Exception as e:
        flash(f"Error generating statement: {str(e)}", "danger")
        return redirect(url_for('loanbook'))





@app.route("/customer/debug-loans/<file_number>")
def customer_debug_loans(file_number):
    customer = Customer.query.filter_by(file_number=file_number).first_or_404()
    loans = LoanApplication.query.filter_by(customer_id=customer.id).all()
    return {
        "customer": f"{customer.first_name} {customer.last_name}",
        "loan_count": len(loans),
        "loans": [{ "id": l.id, "number": l.loan_number, "amount": l.loan_amount } for l in loans]
    }


@app.route('/create-admin')
def create_admin():
    if not User.query.filter_by(username='admin').first():
        # 🔍 Fetch the actual Role object
        admin_role = Role.query.filter_by(name='admin').first()
        if not admin_role:
            flash("Admin role doesn't exist. Run `flask init-rbac` first.", "danger")
            return redirect(url_for('home'))
        
        admin = User(
            username='admin',
            email='admin@example.com',
            role=admin_role,  # ✅ Assign the Role object
            active=True
        )
        admin.set_password('admin123')  # ✅ hash password
        db.session.add(admin)
        db.session.commit()
        flash('Admin user created', 'success')
    else:
        flash('Admin user already exists', 'warning')
    return redirect(url_for('home'))

# Add these routes to your app.py

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/')
@login_required
def home():
    return render_template('home.html')

@app.route('/document/<int:doc_id>')
def view_document(doc_id):
    doc = Document.query.get_or_404(doc_id)
    directory = os.path.dirname(doc.path)
    filename = os.path.basename(doc.path)
    return send_from_directory(directory, filename)


@app.route('/register', methods=['GET', 'POST'])
@role_required("sales_ops", "admin")
def register_customer_debug():
    if request.method == 'POST':
        file = request.files.get('csv_file')
        if file and file.filename.endswith('.csv'):
            # Handle CSV upload
            try:
                stream = io.StringIO(file.stream.read().decode("UTF8"), newline=None)
                csv_input = csv.DictReader(stream)
                for row in csv_input:
                    process_customer_registration(row)
                flash("CSV upload processed successfully.", "success")
            except Exception as e:
                db.session.rollback()
                flash(f"CSV upload failed: {str(e)}", "danger")
            return redirect(url_for('register_customer_debug'))
        else:
            # Manual entry
            try:
                process_customer_registration(request.form)
                flash("Customer and loan registered successfully.", "success")
            except Exception as e:
                db.session.rollback()
                flash(str(e), "danger")
            return redirect(url_for('register_customer_debug'))
    return render_template('register_customer_debug.html')

def process_customer_registration(data):

    try:
        loan_amount = float(data.get('loan_amount', 0))
        if loan_amount < 0:
            raise ValueError("Loan amount cannot be negative")
    except (TypeError, ValueError):
        loan_amount = 0.0

    term_months = int(data['loan_term'])
    loan_amount = float(data['loan_amount'])
    category_code = int(data.get('loan_category'))

    CATEGORY_MAP = {
        1: {'prefix': '1', 'label': 'civil_servant'},
        2: {'prefix': '2', 'label': 'private_sector'},
        3: {'prefix': '3', 'label': 'sme'}
    }

    category_info = CATEGORY_MAP.get(category_code)
    if not category_info:
        raise Exception("Invalid loan category selected.")

    prefix = category_info['prefix']
    category = category_info['label']

    config = PRICING.get(term_months)
    if not config:
        raise Exception("Invalid loan term selected.")

    crb_fees = 3000
    origination_fees = loan_amount * config['origination']
    insurance_fees = loan_amount * config['insurance']
    collection_fees = loan_amount * config['collection']
    capitalized_amount = loan_amount + origination_fees + insurance_fees + crb_fees

    annuity_factor = (config['rate'] * (1 + config['rate']) ** term_months) / \
                     ((1 + config['rate']) ** term_months - 1)
    monthly_instalment = (capitalized_amount * annuity_factor) + collection_fees

    if Customer.query.filter_by(email=data['email']).first():
        raise Exception("Email already exists.")
    if Customer.query.filter_by(national_id=data['national_id']).first():
        raise Exception("National ID already exists.")

    now = datetime.utcnow()
    customer_count = db.session.query(Customer).count()
    file_sequence = str(customer_count + 1).zfill(6)
    file_number = f"{now.year}{str(now.month).zfill(2)}{file_sequence}"

    customer = Customer(
        national_id=data['national_id'],
        first_name=data['first_name'],
        last_name=data['last_name'],
        gender=data.get('gender'),
        dob=data.get('dob'),
        title=data.get('title'),
        email=data['email'],
        contact=data.get('contact'),
        address=data.get('address'),
        employer=data['employer'],
        job_title=data.get('job_title'),
        salary=float(data.get('salary') or 0),
        service_length=data.get('service_length'),
        bank_name=data.get('bank_name'),
        bank_account=data['bank_account'],
        salary_deposited=data.get('salary_deposited'),
        district=data.get('district'),
        region=data.get('region'),
        amount_requested=loan_amount,
        next_of_kin_relationship=data.get("next_of_kin_relationship"),
        next_of_kin_contact=data.get("next_of_kin_contact"),
        next_of_kin_name=data.get('next_of_kin_name'),
        file_number=file_number,
        status=data.get('status', 'pending'),
        is_approved_for_creation=False,
        maker_id=1
    )

    db.session.add(customer)
    db.session.flush()

    document_types = {
        'national_id_front': 'id_front',
        'form': 'form',
        'customer_photo': 'photo',
        'payslip': 'payslip',
        'bank_statement': 'bank_statement',
        'letter_of_undertaking': 'undertaking_letter'
    }

    for form_field, doc_type in document_types.items():
        file = request.files.get(form_field)
        if file:
            filename, filepath = save_document(file, customer.id, doc_type)
            if filename:
                document = Document(
                    customer_id=customer.id,
                    filename=filename,
                    filetype=doc_type,
                    path=filepath
                )
                db.session.add(document)

    tenure = str(term_months).zfill(2)
    loan_count = db.session.query(LoanApplication).count()
    loan_sequence = str(loan_count + 1).zfill(6)
    loan_number = f"{prefix}{tenure}{loan_sequence}"

    # 🧠 UNIVERSAL cash to client logic
    previous_loan = LoanApplication.query.filter_by(customer_id=customer.id).order_by(LoanApplication.id.desc()).first()

    top_up_balance = 0
    if previous_loan:
        # Example of a valid top-up loan: if it's active or closed recently
        if previous_loan.loan_state in ['active', 'closed']:  
            balances = calculate_balances(previous_loan)
            top_up_balance = balances.get('top_up_balance', 0)

    cash_to_client = max(loan_amount - top_up_balance, 0)

    loan = LoanApplication(
        customer_id=customer.id,
        loan_amount=loan_amount,
        term_months=term_months,
        monthly_instalment=round(monthly_instalment, 2),
        total_repayment=round(monthly_instalment * term_months, 2),
        effective_rate=calculate_eir(loan_amount, term_months, config),
        category=category,
        loan_category=category_code,
        loan_number=loan_number,
        file_number=file_number,
        application_status='pending',
        loan_state='application',
        performance_status='pending',
        crb_fees=crb_fees,
        origination_fees=round(origination_fees, 2),
        insurance_fees=round(insurance_fees, 2),
        collection_fees=round(collection_fees, 2),
        cash_to_client=round(cash_to_client, 2)
    )

    db.session.add(loan)
    db.session.flush()


    loan.generate_repayment_schedule()

# --- Insert disbursement record
    disbursement = Disbursement(
        loan_id=loan.id,
        amount=cash_to_client,
        method='bank',
        status='pending',
        reference=f"Initial disbursement for {loan.loan_number}"
    )
    db.session.add(disbursement)

    db.session.commit()

    db.session.commit()




@app.route('/customers')
def customers():
    approved_customers = Customer.query.filter_by(is_approved_for_creation=True).all()
    return render_template('customers_list.html', customers=approved_customers)

@app.route('/approve_customers', methods=['GET', 'POST'])
def approve_customers():
    if request.method == 'POST':
        selected_ids = request.form.getlist('customer_ids')
        if selected_ids:
            customers = Customer.query.filter(Customer.id.in_(selected_ids)).all()
            for customer in customers:
                customer.is_approved_for_creation = True
                customer.checker_id = 2

                if not customer.loans:
                    loan = LoanApplication(
                        customer_id=customer.id,
                        loan_amount=customer.amount_requested or 0.0,
                        loan_category="SME",
                        status='pending',
                        loan_state='Active',
                        application_status='awaiting_approval'
                    )
                    db.session.add(loan)
                else:
                    for loan in customer.loans:
                        loan.status = 'pending'

            db.session.commit()
            flash(f"{len(customers)} customer(s) approved!", "success")
        else:
            flash("No customers selected.", "warning")
        return redirect(url_for('approve_customers'))

    unapproved_customers = Customer.query.filter_by(is_approved_for_creation=False).all()

    # Normalize amount_requested safely here before passing to template
    for customer in unapproved_customers:
        try:
            customer.amount_requested = float(customer.amount_requested)
        except (TypeError, ValueError):
            customer.amount_requested = 0.0

    return render_template('approve_customers.html', customers=unapproved_customers)



@app.route('/customer/<int:customer_id>')
def view_customer(customer_id):
    customer = Customer.query.get_or_404(customer_id)
    return render_template('view_customer.html', customer=customer)

@app.route('/customer/<int:customer_id>/edit', methods=['GET', 'POST'])
@role_required("admin")
def edit_customer(customer_id):
    customer = Customer.query.get_or_404(customer_id)
    if request.method == 'POST':
        customer.first_name = request.form['first_name']
        customer.last_name = request.form['last_name']
        customer.email = request.form['email']
        customer.contact = request.form['contact']
        customer.address = request.form['address']
        customer.employer = request.form['employer']
        customer.bank_account = request.form['bank_account']
        customer.gender = request.form['gender']
        customer.district = request.form['district']
        customer.region = request.form['region']
        db.session.commit()
        flash('Customer details updated successfully!', 'success')
        return redirect(url_for('view_customer', customer_id=customer.id))
    return render_template('edit_customer.html', customer=customer)

@app.route('/loans')
def view_loans():
    # Fetch loan applications where the customer is approved for creation and the loan status is 'pending' or 'approved'
    loans = LoanApplication.query \
        .join(Customer) \
        .filter(Customer.is_approved_for_creation == True) \
        .filter(LoanApplication.status.in_(['pending', 'approved'])) \
        .add_entity(Customer) \
        .all()
    
    processed_loans = []
    for loan_app, customer in loans:
        processed_loans.append({
            'loan': loan_app,
            'customer': customer
        })

    return render_template('view_loans.html', loans=processed_loans)
       
@app.route('/process_loan/<int:loan_id>/<action>', methods=['POST'])
def process_loan(loan_id, action):
    loan = LoanApplication.query.get_or_404(loan_id)

    if action == 'approve':
        loan.application_status = 'approved'
        loan.loan_state = 'active'
        flash('Loan approved successfully.', 'info')

    elif action == 'reject':
        loan.application_status = 'rejected'
        loan.loan_state = None  # or leave as-is
        flash('Loan rejected successfully.', 'info')

    db.session.commit()
    return redirect(url_for('view_loans'))


@app.route('/loan-form/<int:customer_id>', methods=['GET', 'POST'])
def loan_form(customer_id):
    customer = Customer.query.get_or_404(customer_id)

    if not customer.is_approved_for_creation:
        flash("Customer not approved yet.", "danger")
        return redirect(url_for('customers'))

    loan = LoanApplication.query.filter_by(customer_id=customer.id).first()
    if not loan:
        flash("Loan application not found.", "warning")
        return redirect(url_for('customers'))

    if request.method == 'POST':
        loan.amount = float(request.form.get('loan_amount') or loan.amount)
        loan.status = 'approved'
        db.session.commit()
        flash("Loan updated successfully.", "success")

    return render_template('loan_form.html', customer=customer, loan=loan)

@app.route('/approve_loans', methods=['GET', 'POST'])
def approve_loans():
    if request.method == 'POST':
        loan_ids = request.form.getlist('loan_ids')
        if loan_ids:
            loans = LoanApplication.query.filter(LoanApplication.id.in_(loan_ids)).all()
            for loan in loans:
                loan.application_status = 'approved'  # Correct field
            db.session.commit()
            flash(f'{len(loans)} loan(s) approved.', 'success')
        else:
            flash("No loans selected.", 'warning')
        return redirect(url_for('approve_loans'))

    loans = LoanApplication.query\
        .join(Customer)\
        .filter(Customer.is_approved_for_creation == True)\
        .filter(LoanApplication.status == 'pending')\
        .all()

    return render_template('approve_loans.html', loans=loans)

def generate_loan_and_file_number(category_prefix: str, term_months: int, customer_count: int, loan_count: int):
    file_sequence = str(customer_count + 1).zfill(6)
    loan_sequence = str(loan_count + 1).zfill(6)
    now = datetime.utcnow()
    file_number = f"{now.year}{str(now.month).zfill(2)}{file_sequence}"
    loan_number = f"{category_prefix}{str(term_months).zfill(2)}{loan_sequence}"
    return loan_number, file_number

@app.route('/customer/check/<int:customer_id>', methods=['GET', 'POST'])
def check_customer(customer_id):
    customer = Customer.query.get_or_404(customer_id)
    if request.method == 'POST':
        customer.checker_id = 2
        customer.is_approved_for_creation = True
        if customer.loan:
            customer.loan.status = 'approved'
        db.session.commit()
        flash("Customer and loan approved.", "success")
        return redirect(url_for('customers'))
    return render_template('check_customer.html', customer=customer)

@app.route('/create_existing_loan', methods=['GET', 'POST'])
def create_existing_loan():
    if request.method == 'POST':
        try:
            data = request.form
            customer_id = int(data['customer_id'])  # Assuming the customer ID is passed in the form
            term_months = int(data['loan_term'])
            loan_amount = float(data['loan_amount'])
            category = data.get('category')

            # Find the existing customer by ID
            customer = Customer.query.get(customer_id)
            if not customer:
                flash("Customer not found.", "danger")
                return redirect(url_for('create_existing_loan'))

            # Check if loan details are valid
            config = PRICING.get(term_months)
            if not config:
                flash("Invalid loan term selected", "danger")
                return redirect(url_for('create_existing_loan'))

            # --- Fee calculations ---
            crb_fees = 3000  # Fixed CRB fee
            origination_fees = loan_amount * config['origination']
            insurance_fees = loan_amount * config['insurance']
            collection_fees = loan_amount * config['collection']

            capitalized_amount = loan_amount + origination_fees + insurance_fees + crb_fees

            # Monthly repayment calculation
            annuity_factor = (config['rate'] * (1 + config['rate']) ** term_months) / \
                             ((1 + config['rate']) ** term_months - 1)
            monthly_instalment = (capitalized_amount * annuity_factor) + collection_fees

            # --- Generate Loan Number and File Number ---
            loan_number, file_number = generate_loan_and_file_number(category, term_months, db.session)

            # --- Create Loan Application ---
            loan = LoanApplication(
                customer_id=customer.id,
                loan_amount=loan_amount,
                term_months=term_months,
                monthly_instalment=round(monthly_instalment, 2),
                total_repayment=round(monthly_instalment * term_months, 2),
                effective_rate=calculate_eir(loan_amount, term_months, config),
                category=category,
                loan_category=1,  # Adjust if necessary
                status='pending',
                crb_fees=crb_fees,
                origination_fees=round(origination_fees, 2),
                insurance_fees=round(insurance_fees, 2),
                collection_fees=round(collection_fees, 2),
                loan_number=loan_number,  # Assign the loan number
                file_number=file_number  # Assign the file number
            )

            db.session.add(loan)
            db.session.commit()

            flash("Loan created successfully for existing customer. Awaiting approval.", "success")
            return redirect(url_for('loanbook'))  # Adjust to where you want to redirect

        except (KeyError, ValueError) as e:
            db.session.rollback()
            flash(f"Input error: {str(e)}", "danger")
        except IntegrityError:
            db.session.rollback()
            flash("Duplicate entry detected. Check loan details.", "danger")
        except Exception as e:
            db.session.rollback()
            flash(f"An unexpected error occurred: {e}", "danger")

        return redirect(url_for('create_existing_loan'))

    return render_template('create_existing_loan.html')

import logging
# -------- Disbursement Routes --------

@app.route('/disbursements', methods=['GET', 'POST'])
@role_required("admin")
def disbursements():
    from sqlalchemy.orm import joinedload
    from datetime import datetime

    if request.method == 'POST':
        selected_ids = request.form.getlist('loan_ids[]')
        selected_bank = request.form.get('bank')

        if not selected_bank:
            flash("Please select a bank.", "warning")
            return redirect(url_for('disbursements'))

        if not selected_ids:
            flash("No loans selected for disbursement.", "warning")
            return redirect(url_for('disbursements'))

        loans_to_process = LoanApplication.query \
            .options(joinedload(LoanApplication.payments).joinedload(Payment.allocation)) \
            .join(Customer) \
            .filter(LoanApplication.id.in_(selected_ids)) \
            .filter(LoanApplication.application_status == 'approved') \
            .filter(LoanApplication.disbursed == False) \
            .filter(Customer.is_approved_for_creation == True) \
            .all()

        for loan in loans_to_process:
            try:
                # Use precomputed value or fallback to loan_amount
                cash = loan.cash_to_client if loan.cash_to_client is not None else loan.loan_amount
                loan.cash_to_client = round(float(cash), 2)

                loan.disbursed = True
                loan.disbursed_bank = selected_bank
                loan.disbursement_date = datetime.utcnow().date()
                loan.generate_repayment_schedule()
                db.session.add(loan)

                disbursement = Disbursement(
                    loan_id=loan.id,
                    amount=loan.cash_to_client,
                    method=selected_bank.lower(),
                    status='successful',
                    reference=f"{loan.loan_number}-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"
                )
                db.session.add(disbursement)

            except Exception as e:
                db.session.rollback()
                app.logger.error(f"[DISBURSE] Error for loan {loan.loan_number}: {e}")
                flash(f"Error processing loan #{loan.loan_number}", "danger")

        db.session.commit()
        flash("Disbursement complete.", "success")

        try:
            generate_disbursement_letter(loans_to_process, selected_bank)
        except Exception as e:
            app.logger.error(f"[DISBURSEMENT LETTER] Failed to generate letter: {e}")

        return redirect(url_for('disbursements'))

    # GET request
    loans = db.session.query(LoanApplication) \
        .join(Customer, LoanApplication.customer_id == Customer.id) \
        .options(
            joinedload(LoanApplication.customer),
            joinedload(LoanApplication.parent_loan)
                .joinedload(LoanApplication.payments)
                .joinedload(Payment.allocation)
        ) \
        .filter(LoanApplication.application_status == 'approved') \
        .filter(LoanApplication.disbursed == False) \
        .filter(Customer.is_approved_for_creation == True) \
        .all()

    # Use stored `cash_to_client` or fallback to loan_amount
    for loan in loans:
        if loan.cash_to_client is None:
            loan.cash_to_client = float(loan.loan_amount)

        app.logger.info(f"[DISBURSEMENT] Loan #{loan.loan_number} | Top-up of: {loan.top_up_of} | Cash to Client: {loan.cash_to_client}")

    return render_template('disbursements.html', loans=loans, selected_bank=request.form.get('bank'))

def calculate_eir(principal, months, config):
    # Same calculation as in the frontend
    monthly_rate = config['rate']
    balance = principal
    total_interest = 0
    total_balances = 0

    for _ in range(months):
        interest = balance * monthly_rate
        total_interest += interest
        total_balances += balance
        balance -= principal / months  # Simple principal reduction

    fees = (principal * (config['origination'] + config['insurance'])) + config['crb']
    average_balance = total_balances / months
    return round(((total_interest + fees) / average_balance) * (12 / months) * 100, 2)


def generate_disbursement_letter(loans, bank_name):
    bank_headers = {
        "NBS Bank": {
            "address": "P.O. Box 30322, Blantyre 3, Malawi",
            "phone": "+265 1 822 488",
            "email": "nbs@nbs.mw",
            "attention": "The Branch Manager\nNBS Bank"
        },
        "National Bank": {
            "address": "P.O. Box 945, Blantyre, Malawi",
            "phone": "+265 1 820 622",
            "email": "info@natbankmw.com",
            "attention": "The Branch Manager\nNational Bank"
        },
        "Standard Bank": {
            "address": "P.O. Box 30380, Blantyre 3, Malawi",
            "phone": "+265 1 820 600",
            "email": "info@standardbank.co.mw",
            "attention": "The Branch Manager\nStandard Bank"
        },
        "First Capital Bank": {
            "address": "P.O. Box 1111, Blantyre, Malawi",
            "phone": "+265 1 822 123",
            "email": "info@firstcapitalbank.co.mw",
            "attention": "The Branch Manager\nFirst Capital Bank"
        }
    }

    bank_info = bank_headers.get(bank_name, {
        "address": "Unknown Address",
        "phone": "Unknown",
        "email": "Unknown",
        "attention": f"The Branch Manager\n{bank_name}"
    })

    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()
    pdf.set_font("Arial", size=12)

    # Add company logo with proper error handling
    try:
        image_url = "https://i.ibb.co/fdhSBv37/Kwacha-Access-Header-Better.png"
        pdf.image(image_url, x=20, y=10, w=170)  # Centered image with proper dimensions
        pdf.ln(40)  # Add space after the image
    except Exception as e:
        app.logger.error(f"Error inserting image: {str(e)}")
        pdf.ln(20)  # Add default space if image fails

    # Bank details
    pdf.set_font("Arial", '', 12)
    pdf.multi_cell(0, 8,
f"""{bank_info['attention']}
{bank_info['address']}
Phone: {bank_info['phone']}
Email: {bank_info['email']}

Dear Sir/Madam,

SUBJECT: FUNDS TRANSFER INSTRUCTION ACCOUNT NUMBER: 24975600

Please find below the list of beneficiaries for funds transfer from our account:

""")
    pdf.ln(8)

    # Table with new columns
    col_widths = {
        'name': 50,  # 50mm
        'bank': 30,  # 30mm
        'account': 40,  # 40mm
        'amount': 30   # 30mm (total 140mm will auto-wrap)
    }
    pdf.set_font("Arial", 'B', 11)
    pdf.cell(col_widths['name'], 8, "Customer Name", border=1)
    pdf.cell(col_widths['bank'], 8, "Bank Name", border=1)
    pdf.cell(col_widths['account'], 8, "Account Number", border=1)
    pdf.cell(col_widths['amount'], 8, "Amount (MWK)", border=1, ln=True)

    pdf.set_font("Arial", size=11)
    for loan in loans:
        customer = loan.customer
        pdf.cell(col_widths['name'], 8, f"{customer.first_name} {customer.last_name}", border=1)
        pdf.cell(col_widths['bank'], 8, customer.bank_name, border=1)
        pdf.cell(col_widths['account'], 8, customer.bank_account, border=1)
        pdf.cell(col_widths['amount'], 8, f"{loan.cash_to_client:,.2f}", border=1, ln=True)

    pdf.ln(10)

    pdf.multi_cell(0, 8, "Thank you for your continued support.\n\nYours faithfully,\n\nSlyvester Malumba\nCHIEF EXECUTIVE OFFICER")

    pdf.set_y(-30)
    if pdf.page_no() == 1:
        pdf.set_font("Arial", 'I', 8)
        pdf.cell(0, 10, "Directors: Joe Kamalizeni, Margaret Munthali, Hariet Marian, Naomi Nyirenda, Grace Chipofya, Dr Damiano Kaufa, Dyson Mwadzera", 0, 0, 'C')

    # Return PDF as download
    pdf_output = BytesIO()
    pdf_bytes = pdf.output(dest='S')  # Keep as bytes without additional encoding
    pdf_output.write(pdf_bytes)
    pdf_output.seek(0)

    return send_file(
        pdf_output,
        as_attachment=True,
        download_name='funds_transfer_instruction.pdf',
        mimetype='application/pdf'
    )

@app.route('/payments', methods=['GET', 'POST'], endpoint='payments')
@role_required("finance_officer", "admin")
def handle_payments():
    loan = None
    
    if request.method == 'POST':
        is_batch = 'file' in request.files
        
        try:
            if is_batch:
                file = request.files['file']
                if not file.filename.endswith('.csv'):
                    flash('Only CSV files are allowed', 'danger')
                    return redirect(url_for('payments'))

                stream = io.TextIOWrapper(file.stream, encoding='utf8')
                csv_reader = csv.DictReader(stream)
                
                success = 0
                errors = []
                
                for row in csv_reader:
                    try:
                        # Normalize keys to lowercase and strip whitespace
                        normalized_row = {k.strip().lower(): v.strip() for k, v in row.items()}
                        
                        # Get required fields with case-insensitive keys
                        loan_number = normalized_row.get('loan_number', '').strip()
                        if not loan_number:
                            errors.append(f"Missing loan_number in row: {row}")
                            continue
                            
                        # Handle amount formatting (e.g., "107,624.61" -> 107624.61)
                        amount_str = normalized_row.get('amount', '').replace(',', '')
                        try:
                            amount = float(amount_str)
                        except ValueError:
                            errors.append(f"Invalid amount '{amount_str}' for loan {loan_number}")
                            continue
                            
                        # Find loan (case-sensitive match)
                        loan = LoanApplication.query.filter_by(loan_number=loan_number).first()
                        if not loan:
                            errors.append(f"Loan {loan_number} not found")
                            continue
                            
                        # Create payment with optional fields
                        payment = Payment(
                            loan_id=loan.id,
                            amount=amount,
                            method=normalized_row.get('method', 'Batch Upload'),  # Use CSV method if available
                            reference=normalized_row.get('reference', '')
                        )
                        db.session.add(payment)
                        success += 1
                        
                    except Exception as e:
                        errors.append(f"Error processing row {row}: {str(e)}")
                        continue
                        
                db.session.commit()
                flash(f"Processed {success} payments, {len(errors)} errors", 'info')
                if errors:
                    flash('First 5 errors: ' + ' | '.join(errors[:5]), 'warning')

            else:
                # Single payment processing
                loan_number = request.form.get('loan_number', '').strip().upper()
                amount = float(request.form.get('amount'))
                
                loan = LoanApplication.query.filter_by(loan_number=loan_number).first()
                
                if not loan:
                    flash(f'Loan {loan_number} not found', 'danger')
                    return redirect(url_for('payments'))
                
                payment = Payment(
                    loan_id=loan.id,
                    amount=amount,
                    method=request.form.get('method'),
                    reference=request.form.get('reference')
                )
                
                db.session.add(payment)
                db.session.commit()
                flash('Payment recorded successfully', 'success')

        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Payment error: {str(e)}", exc_info=True)
            flash(f'Payment failed: {str(e)}', 'danger')

        return redirect(url_for('payments'))

    # GET request handling
    loan_number = request.args.get('loan_number')
    if loan_number:
        loan = LoanApplication.query.filter_by(loan_number=loan_number).first()
    
    return render_template('payments.html', loan=loan)


@app.route('/api/verify_loan/<loan_number>')
def verify_loan(loan_number):
    loan = LoanApplication.query.filter_by(loan_number=loan_number).first()
    if not loan:
        return jsonify({"error": "Loan not found"}), 404
    
    return jsonify({
        "loan_number": loan.loan_number,
        "customer": f"{loan.customer.first_name} {loan.customer.last_name}",
        "balance": loan.balance,
        "monthly_instalment": loan.monthly_instalment
    })

@app.route('/admin/delete_test_payments')
@role_required("finance_officer", "admin")
def delete_test_payments():
    test_payments = Payment.query.filter(Payment.reference.like("TEST%")).all()
    count = len(test_payments)
    
    for p in test_payments:
        db.session.delete(p)
    db.session.commit()

    flash(f"Deleted {count} test payments", "success")
    return redirect(url_for("admin.dashboard"))


def update_schedule_status(loan):
    schedules = sorted(loan.repayment_schedule, key=lambda r: r.due_date)
    payments = sorted(loan.payments, key=lambda p: p.created_at)

    # Total allocations (from your allocation model)
    payment_map = [
        {
            'date': p.created_at.date(),
            'principal': p.allocation.principal if p.allocation else 0,
            'interest': p.allocation.interest if p.allocation else 0,
            'fees': p.allocation.fees if p.allocation else 0
        }
        for p in payments if p.allocation
    ]

    for sched in schedules:
        if sched.status == 'paid':
            continue

        # Expected total for this schedule
        expected_total = (sched.expected_principal or 0) + (sched.expected_interest or 0) + (sched.expected_fees or 0)

        # Try to find a payment to cover this
        total_paid = 0
        for p in payment_map:
            p_total = p['principal'] + p['interest'] + p['fees']
            if p_total <= 0:
                continue

            # Use it
            total_paid += p_total

            # Consume the allocation
            p['principal'] = 0
            p['interest'] = 0
            p['fees'] = 0

            if total_paid >= expected_total:
                break

        # Update schedule status
        if total_paid >= expected_total:
            sched.status = 'paid'
        elif total_paid > 0:
            sched.status = 'partial'
        else:
            sched.status = 'due'

    db.session.commit()

from flask import request, jsonify, render_template_string

from flask import request, jsonify, render_template, flash, redirect, url_for
from sqlalchemy.orm import joinedload

@app.route('/loanbook')
def loanbook():
    try:
        page = int(request.args.get("page", 1))
        per_page = 25
        ajax = request.args.get("ajax") == "true"

        loans_query = LoanApplication.query \
            .join(Customer, LoanApplication.customer_id == Customer.id) \
            .options(joinedload(LoanApplication.payments).joinedload(Payment.allocation))

        all_loans = loans_query.all()

        processed_loans = []
        for loan in all_loans:
            customer = loan.customer
            config = PRICING.get(loan.term_months or 0, {})
            loan_amount = loan.loan_amount or 0

            capitalized = (
                loan_amount
                + (loan_amount * config.get('origination', 0))
                + (loan_amount * config.get('insurance', 0))
                + config.get('crb', 0)
            )

            total_principal_paid = sum(
                (p.allocation.principal or 0) for p in loan.payments if p.allocation
            )
            remaining_balance = capitalized - (total_principal_paid or 0)

            processed_loans.append({
                'customer': {
                    'first_name': customer.first_name,
                    'last_name': customer.last_name,
                    'file_number': customer.file_number
                },
                'loan': {
                    'loan_number': loan.loan_number,
                    'amount': loan_amount,
                    'term': loan.term_months,
                    'category': loan.category,
                    'monthly_instalment': loan.monthly_instalment,
                    'total_repayment': loan.total_repayment,
                    'balance': round(remaining_balance, 2),
                    'disbursed': loan.disbursed,
                    'collection_fee': loan_amount * config.get('collection', 0)
                },
                'fees': {
                    'crb': config.get('crb', 0),
                    'origination': loan_amount * config.get('origination', 0),
                    'insurance': loan_amount * config.get('insurance', 0),
                    'total': (
                        config.get('crb', 0)
                        + (loan_amount * config.get('origination', 0))
                        + (loan_amount * config.get('insurance', 0))
                    )
                }
            })

        # Pagination logic
        total_loans = len(processed_loans)
        start = (page - 1) * per_page
        end = start + per_page
        paginated_loans = processed_loans[start:end]
        has_next = end < total_loans

        if ajax:
            html = render_template("partials/_loan_rows.html", loans=paginated_loans)

            ajax_totals = {
                "loan_amount": sum(loan["loan"]["amount"] or 0 for loan in paginated_loans),
                "crb_fees": sum(loan["fees"]["crb"] or 0 for loan in paginated_loans),
                "origination_fees": sum(loan["fees"]["origination"] or 0 for loan in paginated_loans),
                "insurance_fees": sum(loan["fees"]["insurance"] or 0 for loan in paginated_loans),
                "total_fees": sum(loan["fees"]["total"] or 0 for loan in paginated_loans),
                "collection_fees": sum(
                    loan["loan"]["collection_fee"] * (loan["loan"]["term"] or 0)
                    for loan in paginated_loans
                ),
                "total_balance": sum(loan["loan"]["balance"] or 0 for loan in paginated_loans),
                "monthly_instalment": sum(loan["loan"]["monthly_instalment"] or 0 for loan in paginated_loans),
                "total_repayment": sum(loan["loan"]["total_repayment"] or 0 for loan in paginated_loans)
            }

            return jsonify({
                "html": html,
                "has_next": has_next,
                "totals": ajax_totals
            })

        # Totals for full (non-AJAX) page
        totals = {
            "loan_amount": sum(loan["loan"]["amount"] or 0 for loan in processed_loans),
            "crb_fees": sum(loan["fees"]["crb"] or 0 for loan in processed_loans),
            "origination_fees": sum(loan["fees"]["origination"] or 0 for loan in processed_loans),
            "insurance_fees": sum(loan["fees"]["insurance"] or 0 for loan in processed_loans),
            "total_fees": sum(loan["fees"]["total"] or 0 for loan in processed_loans),
            "collection_fees": sum(
                loan["loan"]["collection_fee"] * (loan["loan"]["term"] or 0)
                for loan in processed_loans
            ),
            "total_balance": sum(loan["loan"]["balance"] or 0 for loan in processed_loans),
            "monthly_instalment": sum(loan["loan"]["monthly_instalment"] or 0 for loan in processed_loans),
            "total_repayment": sum(loan["loan"]["total_repayment"] or 0 for loan in processed_loans)
        }

        return render_template(
            'loanbook.html',
            loans=paginated_loans,
            page=page,
            has_next=has_next,
            loan_categories={loan['loan']['category'] for loan in processed_loans if loan['loan']['category']},
            loan_tenures=sorted({loan['loan']['term'] for loan in processed_loans if loan['loan']['term'] is not None}),
            totals=totals
        )

    except Exception as e:
        flash(f"Error loading loan book: {str(e)}", "danger")
        return redirect(url_for('home'))




def save_file(file_obj, subfolder=''):
    if file_obj:
        filename = secure_filename(file_obj.filename)
        upload_dir = os.path.join(app.root_path, 'uploads', subfolder)
        os.makedirs(upload_dir, exist_ok=True)
        file_path = os.path.join(upload_dir, filename)
        file_obj.save(file_path)
        return filename, file_path
    return None, None

# Updated process_topup_registration with automatic payment allocation to original loan

def process_topup_registration(data, base_loan,
                                loan_form=None, bank_payslip=None, live_photo=None):
    try:
        new_amount = float(data['amount_requested'])
        term_months = int(data['tenure'])
    except (ValueError, KeyError) as e:
        raise Exception("Invalid input for loan amount or tenure.")

    category_code = base_loan.loan_category

    CATEGORY_MAP = {
        1: {'prefix': '1', 'label': 'civil_servant'},
        2: {'prefix': '2', 'label': 'private_sector'},
        3: {'prefix': '3', 'label': 'sme'}
    }

    category_info = CATEGORY_MAP.get(category_code)
    config = PRICING.get(term_months)
    if not category_info or not config:
        raise Exception("Invalid loan category or term.")

    # --- Fees
    crb_fees = 3000
    origination_fees = new_amount * config['origination']
    insurance_fees = new_amount * config['insurance']
    collection_fees = new_amount * config['collection']

    def calculate_topup_balance(loan):
        from datetime import datetime

        config = PRICING.get(loan.term_months, {})
        if not config:
            return 0.0

        def calculate_capitalized_amount(loan_amount: float, config: dict) -> float:
            try:
                origination = loan_amount * config.get('origination', 0)
                insurance = loan_amount * config.get('insurance', 0)
                crb = config.get('crb', 0)
                return round(loan_amount + origination + insurance + crb, 2)
            except Exception as e:
                app.logger.warning(f"[TOPUP] Capitalization error: {e}")
                return loan_amount

        capitalized = calculate_capitalized_amount(loan.loan_amount or 0, config)
        monthly_rate = config.get('rate', 0)
        term = loan.term_months or 0

        if monthly_rate > 0 and term > 0:
            factor = (monthly_rate * (1 + monthly_rate) ** term) / ((1 + monthly_rate) ** term - 1)
            annuity = capitalized * factor
        else:
            annuity = 0

        payments = sorted(loan.payments, key=lambda p: p.created_at)
        remaining_balance = capitalized
        payments_made = 0

        for p in payments:
            if p.allocation and p.allocation.principal:
                remaining_balance -= p.allocation.principal
                remaining_balance = max(remaining_balance, 0)
                payments_made += 1

        current_balance = round(remaining_balance, 2)
        remaining_term = max(term - payments_made, 0)

        def projected_interest(months_ahead):
            temp_balance = current_balance
            total_interest = 0.0
            for _ in range(min(months_ahead, remaining_term)):
                if temp_balance <= 0:
                    break
                interest = temp_balance * monthly_rate
                principal = annuity - interest
                principal = min(principal, temp_balance)
                total_interest += interest
                temp_balance -= principal
            return round(total_interest, 2)

        top_up_balance = round(current_balance + projected_interest(3), 2)

        return top_up_balance

        # --- Get amount to settle the old loan
    top_up_balance = calculate_topup_balance(base_loan)
    app.logger.debug(f"[DEBUG] Balance calc for base loan #{base_loan.loan_number}: {top_up_balance}")
    cash_to_client = new_amount - top_up_balance
    if cash_to_client <= 0:
        raise Exception("Requested amount is too low to cover top up.")

    # --- Capitalized amount includes fees (but full new loan is used for annuity math)
    capitalized_amount = new_amount + origination_fees + insurance_fees + crb_fees

    # --- Monthly instalment (add collection fee after annuity)
    annuity_factor = (config['rate'] * (1 + config['rate']) ** term_months) / \
                     ((1 + config['rate']) ** term_months - 1)
    monthly_instalment = (capitalized_amount * annuity_factor) + collection_fees

    # --- Generate new loan number
    now = datetime.utcnow()
    loan_count = db.session.query(LoanApplication).count()
    loan_sequence = str(loan_count + 1).zfill(6)
    tenure = str(term_months).zfill(2)
    prefix = category_info['prefix']
    loan_number = f"{prefix}{tenure}{loan_sequence}"

    # --- Create top-up loan
    topup_loan = LoanApplication(
        customer_id=base_loan.customer_id,
        loan_amount=new_amount,
        term_months=term_months,
        monthly_instalment=round(monthly_instalment, 2),
        total_repayment=round(monthly_instalment * term_months, 2),
        effective_rate=calculate_eir(new_amount, term_months, config),
        category=category_info['label'],
        loan_category=category_code,
        loan_number=loan_number,
        file_number=base_loan.file_number,
        application_status='pending',
        loan_state='application',
        performance_status='pending',
        crb_fees=crb_fees,
        origination_fees=round(origination_fees, 2),
        insurance_fees=round(insurance_fees, 2),
        collection_fees=round(collection_fees, 2),
        top_up_of=base_loan.id,
        top_up_balance=top_up_balance,         # ✅ stored here
        cash_to_client=round(cash_to_client, 2),  # ✅ stored here
        date_created=now,
        disbursement_date=None
    )

    db.session.add(topup_loan)
    db.session.flush()  # Ensure we get topup_loan.id

    disbursement = Disbursement(
    loan_id=topup_loan.id,
    amount=cash_to_client,
    method='bank',  # or determine from UI
    status='pending',  # or 'success' if auto-approved
    reference=f"Top-up disbursement for {topup_loan.loan_number}"
    )
    db.session.add(disbursement)

    # --- Attach documents
    for file_obj, filetype in [
        (loan_form, 'loan_form'),
        (bank_payslip, 'bank_payslip'),
        (live_photo, 'live_photo')
    ]:
        filename, filepath = save_file(file_obj, subfolder=f"topup_loan_{topup_loan.id}")
        if filename:
            doc = Document(
                customer_id=base_loan.customer_id,
                loan_id=topup_loan.id,
                filename=filename,
                filetype=filetype,
                path=filepath,
                uploaded_at=datetime.utcnow()
            )
            db.session.add(doc)

    # --- Repayment Schedule
    topup_loan.generate_repayment_schedule()

    # --- Pay off old loan
    if top_up_balance > 0:
        payment = Payment(
            loan_id=base_loan.id,
            amount=top_up_balance,
            method='internal_topup',
            status='successful',
            reference=f"Top-Up from {loan_number}",
            created_at=datetime.utcnow()
        )
        db.session.add(payment)
        db.session.flush()

        allocate_payment(payment, base_loan)

        base_loan.status = 'closed'
        base_loan.loan_state = 'topped_up'
        base_loan.closure_type = 'topup'
        base_loan.closure_date = datetime.utcnow()

    return topup_loan



@app.route('/loans', methods=['POST'])
def create_loan():
    data = request.get_json()

    try:
        new_loan = LoanApplication(
            customer_id=data.get('customer_id'),
            loan_amount=data.get('amount'),
            parent_loan_id=data.get('parent_loan_id')  # optional
        )
        db.session.add(new_loan)
        db.session.commit()

        return jsonify({'id': new_loan.id, 'message': 'Loan created'}), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

def allowed_file(filename: str) -> bool:
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in {'pdf', 'png', 'jpg', 'jpeg'}

@app.route('/topup/<int:loan_id>', methods=['POST'])
@role_required('sales_ops', 'admin')
def submit_topup(loan_id):
    app.logger.info(f"[TOPUP] Submit route hit for loan {loan_id}")
    base_loan = LoanApplication.query.get_or_404(loan_id)
    data = request.form
    files = request.files

    try:
        new_loan = process_topup_registration(
            data=data,
            base_loan=base_loan,
            loan_form=files.get('loan_form'),
            bank_payslip=files.get('bank_payslip'),
            live_photo=files.get('live_photo')
        )

        # cash_to_client = loan_amount - old loan balance (calculated inside process_topup_registration)
        db.session.commit()

        flash("Top-up loan submitted successfully.", "success")
        return redirect(url_for('customer_account', file_number=base_loan.file_number, section='statement'))

    except Exception as e:
        db.session.rollback()
        flash(f"Failed to submit top-up: {str(e)}", "danger")
        return redirect(request.referrer)



def process_additional_registration(data, base_loan,
                                    loan_form=None, bank_payslip=None, live_photo=None):
    new_amount = float(data['amount_requested'])
    term_months = int(data['tenure'])
    category_code = base_loan.loan_category

    CATEGORY_MAP = {
        1: {'prefix': '1', 'label': 'civil_servant'},
        2: {'prefix': '2', 'label': 'private_sector'},
        3: {'prefix': '3', 'label': 'sme'}
    }

    category_info = CATEGORY_MAP.get(category_code)
    config = PRICING.get(term_months)

    if not category_info or not config:
        raise Exception("Invalid category or term.")

    crb_fees = 3000
    origination_fees = new_amount * config['origination']
    insurance_fees = new_amount * config['insurance']
    collection_fees = new_amount * config['collection']
    capitalized_amount = new_amount + origination_fees + insurance_fees + crb_fees

    annuity_factor = (config['rate'] * (1 + config['rate']) ** term_months) / \
                     ((1 + config['rate']) ** term_months - 1)
    monthly_instalment = (capitalized_amount * annuity_factor) + collection_fees

    now = datetime.utcnow()
    loan_sequence = str(db.session.query(LoanApplication).count() + 1).zfill(6)
    loan_number = f"{category_info['prefix']}{str(term_months).zfill(2)}{loan_sequence}"

    additional_loan = LoanApplication(
        customer_id=base_loan.customer_id,
        loan_amount=new_amount,
        term_months=term_months,
        monthly_instalment=round(monthly_instalment, 2),
        total_repayment=round(monthly_instalment * term_months, 2),
        effective_rate=calculate_eir(new_amount, term_months, config),
        category=category_info['label'],
        loan_category=category_code,
        loan_number=loan_number,
        file_number=base_loan.file_number,
        application_status='pending',
        loan_state='active',
        crb_fees=crb_fees,
        origination_fees=round(origination_fees, 2),
        insurance_fees=round(insurance_fees, 2),
        collection_fees=round(collection_fees, 2),
        parent_loan_id=None,
        date_created=now,
        disbursement_date=None,
        cash_to_client=new_amount  # 💡 assign full amount as cash to client
    )

    db.session.add(additional_loan)
    db.session.flush()

    for file_obj, filetype in [
        (loan_form, 'loan_form'),
        (bank_payslip, 'bank_payslip'),
        (live_photo, 'live_photo')
    ]:
        filename, filepath = save_file(file_obj, subfolder=f"additional_loan_{additional_loan.id}")
        if filename:
            doc = Document(
                customer_id=base_loan.customer_id,
                loan_id=additional_loan.id,
                filename=filename,
                filetype=filetype,
                path=filepath,
                uploaded_at=datetime.utcnow()
            )
            db.session.add(doc)

    additional_loan.generate_repayment_schedule()

    return additional_loan



@app.route('/apply_additional/<int:loan_id>', methods=['POST'])
@role_required('sales_ops', 'admin')
def apply_additional_loan(loan_id):
    base_loan = LoanApplication.query.get_or_404(loan_id)
    

    data = request.form
    files = request.files

    try:
        # Similar logic to process_topup_registration, or you can reuse that function with a different flag
        new_loan = process_additional_registration(
            data=data,
            base_loan=base_loan,
            loan_form=files.get('loan_form'),
            bank_payslip=files.get('bank_payslip'),
            live_photo=files.get('live_photo')
        )

        db.session.commit()
        flash("Additional loan submitted successfully.", "success")
        return redirect(url_for('customer_account', file_number=base_loan.file_number, section='statement'))

    except Exception as e:
        db.session.rollback()
        flash(f"Failed to submit additional loan: {str(e)}", "danger")
        return redirect(request.referrer)


@app.route('/debug_loans')
def debug_loans():
    loans = LoanApplication.query.all()
    output = []

    for loan in loans:
        output.append({
            'Loan ID': loan.id,
            'Loan Status': loan.status,
            'Customer ID': loan.customer_id,
            'Customer Approved': loan.customer.is_approved_for_creation,
            'Customer Name': f"{loan.customer.first_name} {loan.customer.last_name}"
        })

    return {'loans': output}

@app.route('/settle_loan/<int:loan_id>', methods=['POST'])
@login_required
@role_required('finance_officer', 'admin')
def settle_loan(loan_id):
    try:
        loan = LoanApplication.query.get_or_404(loan_id)
        closure_type = request.form.get('closure_type', 'settlement').lower()
        
        # Validate required fields
        if 'settle_file' not in request.files:
            raise ValueError("Settlement proof document is required")
            
        settlement_file = request.files['settle_file']
        if settlement_file.filename == '':
            raise ValueError("No file selected")

        # Calculate settlement amount based on type
        if closure_type == 'settlement':
            amount = loan.settlement_balance  # Principal + interest
        elif closure_type in ['insurance', 'write_off']:
            amount = loan.current_balance  # Principal only
        else:
            raise ValueError("Invalid settlement type")

        # Save settlement proof
        timestamp = datetime.utcnow().strftime('%Y%m%d%H%M%S')
        filename = secure_filename(f"{loan.loan_number}_{closure_type}_{timestamp}_{settlement_file.filename}")
        settlement_dir = os.path.join(app.config['UPLOAD_FOLDER'], 'settlements')
        os.makedirs(settlement_dir, exist_ok=True)
        filepath = os.path.join(settlement_dir, filename)
        settlement_file.save(filepath)

        # Update loan status
        loan.status = 'closed'
        loan.loan_state = 'settled_client' if closure_type == 'settlement' else closure_type
        loan.closure_type = closure_type
        loan.closure_date = datetime.utcnow()
        loan.settlement_amount = amount
        loan.settlement_proof = filename

        # Create settlement payment record
        payment = Payment(
            loan_id=loan.id,
            amount=amount,
            method='settlement',
            status='completed',
            reference=f"{closure_type.replace('_', ' ').title()} Settlement",
            created_at=datetime.utcnow()
        )
        db.session.add(payment)

        db.session.commit()
        flash(f"Loan {loan.loan_number} successfully closed via {closure_type.replace('_', ' ')}", "success")
        return redirect(url_for('customer_account', file_number=loan.customer.file_number))

    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Failed to close loan {loan_id}: {str(e)}", exc_info=True)
        flash(f"Failed to close loan: {str(e)}", "danger")
        return redirect(request.referrer or url_for('loanbook'))

def process_csv_writeoffs(csv_file):
    try:
        if not allowed_file(csv_file.filename, {'csv'}):
            raise ValueError("Only CSV files are allowed")

        stream = io.StringIO(csv_file.stream.read().decode("UTF8"))
        csv_reader = csv.DictReader(stream)
        
        processed = 0
        for row in csv_reader:
            try:
                loan = LoanApplication.query.filter_by(loan_number=row['loan_number']).first()
                if loan and loan.loan_state == 'active':
                    loan.loan_state = 'written_off'
                    loan.closure_type = 'write_off'
                    loan.closure_date = datetime.utcnow()
                    loan.settlement_amount = loan.current_balance
                    db.session.add(loan)
                    processed += 1
            except Exception as e:
                app.logger.error(f"Error processing loan {row.get('loan_number')}: {str(e)}")
                
        db.session.commit()
        flash(f"Successfully processed {processed} write-offs from CSV", "success")
        return redirect(url_for('loanbook'))
        
    except Exception as e:
        db.session.rollback()
        flash(f"CSV processing failed: {str(e)}", "danger")
        return redirect(request.referrer)
    
def validate_journal_entries(loan: LoanApplication):
    try:
        principal_entries = sum(e.amount for e in loan.journal_entries 
                              if e.entry_type == 'principal_recovery')
        interest_entries = sum(e.amount for e in loan.journal_entries 
                             if e.entry_type == 'interest_income')
        
        expected_principal = loan.calculated.current_balance
        expected_interest = getattr(loan, f"{loan.closure_type}_interest", 0)
        
        if not math.isclose(abs(principal_entries), expected_principal, abs_tol=0.01):
            raise AccountingError(f"Principal mismatch: Expected {expected_principal}, Found {abs(principal_entries)}")
        
        if not math.isclose(interest_entries, expected_interest, abs_tol=0.01):
            raise AccountingError(f"Interest mismatch: Expected {expected_interest}, Found {interest_entries}")
            
    except AccountingError as ae:
        app.logger.error(f"Accounting validation failed: {str(ae)}")
        raise
    except Exception as e:
        app.logger.error(f"Validation error: {str(e)}")
        raise AccountingError("General accounting validation failure") from e

def create_tables():
    with app.app_context():
        db.create_all()

def initialize_roles_permissions():
    with app.app_context():
        create_roles_and_permissions()


if __name__ == '__main__':
    # Only create tables if they don't exist
    if not os.path.exists('instance/customers.db'):
        create_tables()
        initialize_roles_permissions()
    app.run(debug=True)