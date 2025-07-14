from flask import Flask, render_template, request, redirect, url_for, flash, send_file, jsonify, abort 
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from sqlalchemy.exc import IntegrityError
from datetime import datetime
from io import BytesIO
from fpdf import FPDF
from datetime import datetime
from sqlalchemy import func
import calendar
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
from flask_migrate import upgrade
from flask.cli import with_appcontext
from dotenv import load_dotenv
from sqlalchemy import Column, String, Enum, ForeignKey
from sqlalchemy.orm import validates
import enum
from concurrent_log_handler import ConcurrentRotatingFileHandler
from flask import Blueprint
# Load environment variables first
load_dotenv()

# Create logs directory if missing
log_dir = os.path.join(os.path.dirname(__file__), 'logs')
if not os.path.exists(log_dir):
    os.makedirs(log_dir)

# Enum class definition
class SettlementTypeEnum(enum.Enum):
    self_settlement = "self"
    third_party = "third_party"
    
    @classmethod
    def get_display_name(cls, value):
        names = {
            "self": "Self Settlement",
            "third_party": "Third Party Settlement"
        }
        return names.get(value.value if isinstance(value, cls) else value, value)

# Initialize Flask application
app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'supersecretkey')

# ======================
# LOGGING CONFIGURATION
# ======================

# Set base logger level
app.logger.setLevel(logging.DEBUG)  # Capture all levels from DEBUG up

# Create common formatter
formatter = logging.Formatter(
    '[%(asctime)s] %(levelname)s in %(module)s: %(message)s'
)

# Handler 1: Main application log (app.log)
main_handler = ConcurrentRotatingFileHandler(
    'app.log',
    mode='a',
    maxBytes=1024 * 1024,   # 1 MB per file
    backupCount=5,
    encoding='utf-8'
)
main_handler.setLevel(logging.INFO)  # Only INFO and higher
main_handler.setFormatter(formatter)
app.logger.addHandler(main_handler)

# Handler 2: Detailed debug log (logs/loan_app.log)
debug_handler = ConcurrentRotatingFileHandler(
    os.path.join(log_dir, 'loan_app.log'),
    mode='a',
    maxBytes=512000,        # 500 KB per file
    backupCount=3,
    encoding='utf-8'
)
debug_handler.setLevel(logging.DEBUG)  # All levels
debug_handler.setFormatter(formatter)
app.logger.addHandler(debug_handler)

# Handler 3: Console output for development
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.DEBUG if app.debug else logging.INFO)
console_handler.setFormatter(formatter)
app.logger.addHandler(console_handler)

# Windows-specific UTF-8 console configuration
if os.name == 'nt':
    import ctypes
    try:
        ctypes.windll.kernel32.SetConsoleCP(65001)
        ctypes.windll.kernel32.SetConsoleOutputCP(65001)
    except Exception as e:
        app.logger.warning(f"Failed to set Windows console encoding: {str(e)}")

# Ensure UTF-8 encoding for stdout/stderr
if sys.stdout.encoding != 'UTF-8':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except AttributeError:
        # Python < 3.7 compatibility
        sys.stdout = open(sys.stdout.fileno(), 'w', encoding='utf-8', errors='replace')

if sys.stderr.encoding != 'UTF-8':
    try:
        sys.stderr.reconfigure(encoding='utf-8')
    except AttributeError:
        sys.stderr = open(sys.stderr.fileno(), 'w', encoding='utf-8', errors='replace')

# Initialization complete
app.logger.info("=" * 50)
app.logger.info("Application logging initialized successfully")
app.logger.info(f"Log directory: {os.path.abspath(log_dir)}")
app.logger.info(f"Python version: {sys.version}")
app.logger.info(f"System encoding: {sys.getdefaultencoding()}")
app.logger.info("=" * 50)


# Add these template filters
@app.template_filter('percent')
def percent_filter(value):
    """Format decimal as percentage (0.035 → 3.500%)"""
    try:
        return f"{float(value)*100:.3f}%"
    except (ValueError, TypeError):
        return "0.000%"

# Make sure this is placed BEFORE any routes that use the filter
@app.template_filter('format_currency')
def format_currency_filter(value):
    """Format number as currency (3000 → 3,000.00)"""
    try:
        return f"{float(value):,.2f}"
    except (ValueError, TypeError):
        return "0.00"

# Also add this filter as a global function for string formatting
@app.context_processor
def utility_processor():
    def format_currency(value):
        try:
            return f"{float(value):,.2f}"
        except (ValueError, TypeError):
            return "0.00"
    return dict(format_currency=format_currency)

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


@app.template_filter('datetimeformat')
def datetimeformat_filter(value, format='%Y-%m-%d %H:%M'):
    """Custom datetime format filter"""
    if value is None:
        return ""
    try:
        return value.strftime(format)
    except AttributeError:
        return ""

app.jinja_env.filters['datetimeformat'] = datetimeformat_filter

# Add this to your app.py where you have other template filters
@app.template_filter('format_currency')
def format_currency_filter(value):
    """Format number as currency (3000 → 3,000.00)"""
    try:
        return f"{float(value):,.2f}"
    except (ValueError, TypeError):
        return "0.00"

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


# Use Postgres in production, SQLite locally
# Database configuration
database_url = os.getenv("DATABASE_URL", "")

if database_url:
    # Fix PostgreSQL URL format if needed
    if database_url.startswith("postgres://"):
        database_url = database_url.replace("postgres://", "postgresql://", 1)
    
    app.config['SQLALCHEMY_DATABASE_URI'] = database_url
    print(f"Connected to PRODUCTION DB: PostgreSQL")
else:
    # Fallback to SQLite for development
    app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///customers.db"
    print("Connected to DEVELOPMENT DB: sqlite:///customers.db")

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

bp = Blueprint('admin', __name__, url_prefix='/admin')
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

# app.py
from flask import send_file, abort
from werkzeug.exceptions import NotFound


@app.route("/documents/id/<int:doc_id>")
@login_required
def serve_document(doc_id: int):
    """
    Streams any uploaded document (image, PDF, DOCX …) back to the browser.
    Large files are forced to download (`as_attachment=True`) so Office apps
    / photo viewers take over.
    """
    doc = Document.query.get_or_404(doc_id)

    try:
        # `download_name` keeps the original filename for the user
        return send_file(
            doc.path,
            as_attachment=doc.filetype not in ("id_front", "id_back", "live_photo", "payslip", "photo"),
            download_name=doc.filename,
            max_age=0               # don’t cache sensitive docs
        )
    except FileNotFoundError:
        raise NotFound("File is missing on the server.")


# ---------------- Pricing Configuration ----------------

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
class PricingConfig(db.Model):
    __tablename__ = 'pricing_configs'
    
    id = db.Column(db.Integer, primary_key=True)
    category = db.Column(db.String(50), nullable=False)  # civil_servant, private_sector, sme
    term_months = db.Column(db.Integer, nullable=False)
    interest_rate = db.Column(db.Float, nullable=False)
    origination_fee = db.Column(db.Float, nullable=False)
    insurance_fee = db.Column(db.Float, nullable=False)
    collection_fee = db.Column(db.Float, nullable=False)
    crb_fee = db.Column(db.Float, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    apply_to_new = db.Column(db.Boolean, default=True)
    apply_to_existing = db.Column(db.Boolean, default=False)
    apply_interest_to_existing = db.Column(db.Boolean, default=False)
    apply_collection_to_existing = db.Column(db.Boolean, default=False)

    __table_args__ = (
        db.UniqueConstraint('category', 'term_months', name='uq_category_term'),
    )


from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

class User(db.Model, UserMixin):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True)  # ✅
    password_hash = db.Column(db.String(512), nullable=False)  # ✅
    email = db.Column(db.String(150), nullable=False)  # ✅
    active = db.Column(db.Boolean, default=True, nullable=False)  # ✅
    role_id = db.Column(db.Integer, db.ForeignKey('roles.id', name='fk_users_role_id'))
    
    role = db.relationship('Role', backref='users')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f'<User {self.username} - Role: {self.role.name}>'  # Access role.name

    __table_args__ = (
        db.UniqueConstraint('username', name='uq_users_username'),
        db.UniqueConstraint('email', name='uq_users_email'),
    )


class Role(db.Model):
    __tablename__ = 'roles'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True)
    permissions = db.relationship('Permission', secondary='role_permissions')

    def has_permission(self, resource, action):
        print(f"\nChecking permission for {resource}:{action}")
        print(f"Role '{self.name}' has {len(self.permissions)} permissions:")
        
        found = False
        for perm in self.permissions:
            print(f" - {perm.resource}:{perm.action}")
            
            # Wildcard match
            if perm.resource == '*' and perm.action == '*':
                print("   WILDCARD PERMISSION FOUND - ACCESS GRANTED")
                found = True
                # Don't return yet to see all permissions
            
            # Exact match
            if perm.resource == resource and perm.action == action:
                print(f"   EXACT MATCH FOUND FOR {resource}:{action}")
                found = True
        
        # Also check for partial wildcards
        for perm in self.permissions:
            if perm.resource == '*' and perm.action == action:
                print(f"   RESOURCE WILDCARD MATCH FOR *:{action}")
                found = True
            if perm.resource == resource and perm.action == '*':
                print(f"   ACTION WILDCARD MATCH FOR {resource}:*")
                found = True
        
        print(f"ACCESS {'GRANTED' if found else 'DENIED'}")
        return found


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
    date_joined = db.Column(db.Date, nullable=True, index=True)
    is_voluntary_retirement_candidate = db.Column(db.Boolean, default=False)

    loans = db.relationship('LoanApplication', back_populates='customer')
    

    def __repr__(self):
        return f'<Customer {self.first_name} {self.last_name}, Status: {self.status}>'

    @property
    def age(self):
        if self.dob:
            today = date.today()
            return today.year - self.dob.year - ((today.month, today.day) < (self.dob.month, self.dob.day))
        return None

    @property
    def years_in_service(self):
        if self.date_joined:
            today = date.today()
            return today.year - self.date_joined.year - ((today.month, today.day) < (self.date_joined.month, self.date_joined.day))
        return None

    @property
    def is_voluntary_retirement_candidate(self):
        return self.years_in_service is not None and self.years_in_service >= 20

@property
def full_name(self):
        return f"{self.first_name} {self.last_name}"

class CutoffDateConfig(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    category = db.Column(db.String(50), unique=True, nullable=False)  # 'civil_servant', 'private_sector', etc.
    cutoff_dt = db.Column(db.DateTime, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


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
    current_balance = db.Column(db.Float, default=0.0)
    settlement_type = Column(Enum(SettlementTypeEnum), nullable=True)
    settling_institution = Column(String(255), nullable=True)  # only if third_party
    settlement_reason = db.Column(db.String(255), nullable=True)
    vote_id = db.Column(db.Integer, db.ForeignKey('votes.id'))
    outstanding_fees = db.Column(db.Float, default=0.0)    
    pricing_version = db.Column(db.Integer, default=1)
    applied_interest_rate = db.Column(db.Float)
    applied_collection_fee = db.Column(db.Float)
    written_off_amount = db.Column(db.Float, default=0.0)
    insurance_settlement_amount = db.Column(db.Float, default=0.0)
    
    parent_loan_id = db.Column(
        db.Integer, 
        db.ForeignKey('loan_applications.id'),
        nullable=True
    )

    vote = db.relationship('Vote', backref='loan_applications')

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
    @validates('settlement_reason')
    def validate_reason(self, key, value):
        allowed_reasons = {"price", "stay debt free", "consolidation", "better terms", "other"}
        if value.lower() not in allowed_reasons:
            raise ValueError(f"Invalid settlement reason: {value}")
        return value.lower()

    @validates("settlement_type")
    def validate_type(self, key, value):
        if value is not None and not isinstance(value, SettlementTypeEnum):
            raise ValueError("Invalid settlement type")
        return value

    @property
    def total_arrears(self):
        return sum(s.arrears_amount for s in self.repayment_schedules)
    
    @property
    def max_arrears_days(self):
        max_days = 0
        for s in self.repayment_schedules:
            if s.due_date < datetime.utcnow().date() and s.status != 'paid':
                days = (datetime.utcnow().date() - s.due_date).days
                if days > max_days:
                    max_days = days
        return max_days
    # In your LoanApplication model
    @property
    def is_topup(self):
        return self.parent_loan_id is not None

    def __repr__(self):
        return f'<LoanApplication for Customer ID {self.customer_id} - Status: {self.status}>'

    
    @property
    def computed_current_balance(self):
        from datetime import datetime

        if self.loan_state in ('settled_client', 'write_off', 'insurance'):
            return 0.0    

        config = get_pricing_config(self.category, self.term_months, self)
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

        capitalized = calculate_capitalized_amount(self.loan_amount or 0, config)
        monthly_rate = config.get('rate', 0)
        term = self.term_months or 0

        if monthly_rate > 0 and term > 0:
            factor = (monthly_rate * (1 + monthly_rate) ** term) / ((1 + monthly_rate) ** term - 1)
            annuity = capitalized * factor
        else:
            annuity = 0

        payments = sorted(self.payments, key=lambda p: p.created_at)
        remaining_balance = capitalized
        payments_made = 0

        for p in payments:
            if p.allocation and p.allocation.principal:
                remaining_balance -= p.allocation.principal
                remaining_balance = max(remaining_balance, 0)
                payments_made += 1

        return round(remaining_balance, 2)

    @property
    def balance(self):
        if self.loan_state in ('settled_client', 'write_off', 'insurance'):
            return 0.0
        
        config = get_pricing_config(self.category, self.term_months, self)
        if not config:
            return None

        capitalized = (
            self.loan_amount +
            (self.loan_amount * config.get('origination', 0)) +
            (self.loan_amount * config.get('insurance', 0)) +
            config.get('crb', 0)
        )

        paid_principal = sum(
        alloc.principal or 0
        for p in self.payments
        for alloc in p.allocations
        )

        return round(capitalized - paid_principal, 2)

    @property
    def total_arrears(self):
        return sum(a.total_arrears for a in self.arrears if a.status == 'unresolved')

    @property
    def calculated_balance(self):
        if self.loan_state in ('settled_client', 'write_off', 'insurance'):
            return 0.0

        config = get_pricing_config(self.category, self.term_months, self)
        if not config:
            return 0.0

        capitalized = (
                self.loan_amount +
                (self.loan_amount * config.get('origination', 0)) +
                (self.loan_amount * config.get('insurance', 0)) +
                config.get('crb', 0)
            )

        paid_principal = sum(
        alloc.principal or 0
        for p in self.payments
        for alloc in p.allocations
        )

        return round(capitalized - paid_principal, 2)   

    
    def recalculate_balance(self):
        """Production-proven balance calculation"""
        # Skip if already closed
        if self.loan_state in {"settled_client", "write_off", "insurance"}:
            self.current_balance = 0.0
            self.top_up_balance = 0.0
            self.settlement_balance = 0.0
            return

        config = get_pricing_config(self.category, self.term_months, self)
        if not config:
            app.logger.error(f"No pricing config for {self.loan_number}")
            return

        # Calculate capitalized amount
        capitalized = (
            self.loan_amount +
            (self.loan_amount * config.get('origination', 0)) +
            (self.loan_amount * config.get('insurance', 0)) +
            config.get('crb', 0)
        )

        # Calculate paid principal (only from successful payments)
        paid_principal = sum(
            alloc.principal
            for payment in self.payments
            if payment.status in ['successful', 'completed']
            for alloc in payment.allocations
        )

        # Calculate current balance
        current_balance = max(round(capitalized - paid_principal, 2), 0.0)
        
        # Update balances based on loan state
        if self.loan_state == 'active':
            self.current_balance = current_balance
            self.top_up_balance = current_balance + (self.top_up_interest or 0.0)
            self.settlement_balance = current_balance + (self.settlement_interest or 0.0)
        else:
            self.current_balance = 0.0
            self.top_up_balance = 0.0
            self.settlement_balance = 0.0

        app.logger.info(
            f"[{self.loan_number}] Recalculated: "
            f"capitalized={capitalized}, paid_principal={paid_principal}, "
            f"current_balance={self.current_balance}"
        )
        
    def get_cutoff_day_for_civil_servant(self) -> int | None:
        """
        Returns an integer 1-31 for the civil-servant cut-off day,
        or None if the admin hasn't set one yet.
        """
        rec = CutoffDateConfig.query.first()
        if rec and rec.cutoff_dt:
            return rec.cutoff_dt.day
        return None

    def get_first_due_date(self, disbursement_date=None):
        """
        Determine the first instalment due date with optional custom disbursement date
        """
        import calendar
        from datetime import date as _date
        from dateutil.relativedelta import relativedelta

        # Use custom disbursement date if provided, otherwise use loan's disbursement date
        disb_date = disbursement_date or (self.disbursement_date or _date.today())
        due_day = 25
        cat = (self.category or "").lower()

        if cat == "private_sector":
            target_month = disb_date if disb_date.day <= 15 else disb_date + relativedelta(months=1)
        elif cat == "civil_servant":
            cutoff_day = self.get_cutoff_day_for_civil_servant()
            target_month = disb_date + relativedelta(months=1)
            if cutoff_day and disb_date.day > cutoff_day:
                target_month += relativedelta(months=1)
        else:
            target_month = disb_date + relativedelta(months=1)

        last_day = calendar.monthrange(target_month.year, target_month.month)[1]
        return target_month.replace(day=min(due_day, last_day))

    def generate_repayment_schedule(self, disbursement_date=None):
        """
        Build/replace this loan's amortised schedule with optional backdating
        """
        from dateutil.relativedelta import relativedelta
        
        # Wipe existing rows
        for sched in self.repayment_schedules:
            db.session.delete(sched)

        # Get pricing config
        config = get_pricing_config(self.category, self.term_months, self)
        if not config:
            return

        loan_amt = self.loan_amount or 0
        origination = loan_amt * config.get('origination', 0)
        insurance = loan_amt * config.get('insurance', 0)
        crb = config.get('crb', 0)
        capitalised = loan_amt + origination + insurance + crb

        monthly_rate = config.get('rate', 0)
        coll_fee_flat = loan_amt * config.get('collection', 0)
        term = self.term_months or 0
        if term <= 0:
            return

        # Get first due date using custom disbursement date if provided
        first_due = self.get_first_due_date(disbursement_date)

        # Calculate annuity payment
        if monthly_rate > 0:
            fac = (monthly_rate * (1 + monthly_rate) ** term) / ((1 + monthly_rate) ** term - 1)
            annuity_princ_int = capitalised * fac
        else:
            annuity_princ_int = capitalised / term

        remaining = capitalised

        # Create new schedule
        for i in range(term):
            due_date = first_due + relativedelta(months=i)
            interest = remaining * monthly_rate
            principal = annuity_princ_int - interest

            # Handle last instalment
            if i == term - 1:
                principal = remaining
                interest = annuity_princ_int - principal
                annuity_princ_int = principal + interest

            remaining -= principal
            remaining = max(0, round(remaining, 2))

            schedule = RepaymentSchedule(
                loan_id=self.id,
                instalment_no=i + 1,
                due_date=due_date,
                expected_principal=round(principal, 2),
                expected_interest=round(interest, 2),
                expected_fees=round(coll_fee_flat, 2),
                expected_amount=round(principal + interest + coll_fee_flat, 2),
                remaining_balance=remaining
            )
            db.session.add(schedule)
    
    # Do NOT commit here - handled by caller

    from datetime import datetime
    from dateutil.relativedelta import relativedelta   # already using
    import calendar

    # … other methods in LoanApplication …

    def allocate_payment(self, payment):
        if self.loan_state in {"settled_client", "write_off", "insurance"}:
            app.logger.warning(f"[{self.loan_number}] Payment not allocated. Loan state is closed: {self.loan_state}")
            return

        remaining = payment.amount
        method = (payment.method or "normal").lower()

        # Normalize payment method
        if "top_up" in method:
            method = "top_up"
        elif "settlement" in method:
            method = "settlement"

        ### 🟩 HANDLE TOP-UP ALLOCATION AND EXIT EARLY
        if method == "top_up":
            principal_alloc = min(self.top_up_balance, remaining)
            self.top_up_balance -= principal_alloc
            remaining -= principal_alloc

            interest_alloc = min(self.top_up_interest or 0.0, remaining)
            self.top_up_interest = (self.top_up_interest or 0.0) - interest_alloc
            remaining -= interest_alloc

            db.session.add(PaymentAllocation(
                payment_id=payment.id,
                principal=principal_alloc,
                interest=interest_alloc,
                fees=0.0
            ))

            app.logger.info(f"[{self.loan_number}] Top-up payment → principal: {principal_alloc}, interest: {interest_alloc}")

            # CLOSE IF FULLY PAID
            if self.top_up_balance <= 0 and self.top_up_interest <= 0:
                self.status = "closed"
                self.loan_state = "settled_client"
                app.logger.info(f"[{self.loan_number}] Loan marked as closed after top-up.")

                # Cancel all schedules since this is a top-up closure
                for schedule in self.repayment_schedules:
                    if schedule.status not in {"paid", "cancelled"}:
                        schedule.status = "cancelled"

            if remaining > 0:
                self.record_loan_credit(payment, remaining)

            return  # ❗ Ensure we do NOT proceed to normal schedule allocation

        ### 🟧 HANDLE SETTLEMENT (Similar Exit)
        if method == "settlement":
            principal_alloc = min(self.current_balance, remaining)
            self.current_balance -= principal_alloc
            remaining -= principal_alloc

            interest_alloc = min(self.settlement_interest or 0.0, remaining)
            self.settlement_interest = (self.settlement_interest or 0.0) - interest_alloc
            remaining -= interest_alloc

            db.session.add(PaymentAllocation(
                payment_id=payment.id,
                principal=principal_alloc,
                interest=0.0,
                settlement_interest=interest_alloc,
                fees=0.0
            ))

            app.logger.info(f"[{self.loan_number}] Settlement payment → principal: {principal_alloc}, interest: {interest_alloc}")

            if self.current_balance <= 0:
                self.status = "closed"
                self.loan_state = "settled_client"
                app.logger.info(f"[{self.loan_number}] Loan marked as closed after settlement.")

                for schedule in self.repayment_schedules:
                    if schedule.status not in {"paid", "cancelled"}:
                        schedule.status = "cancelled"

            if remaining > 0:
                self.record_loan_credit(payment, remaining)

            return

        ### 🟥 NORMAL SCHEDULE ALLOCATION (only reached if NOT top_up/settlement)
        schedules = sorted(self.repayment_schedules, key=lambda s: s.due_date)
        schedule_updated = False

        for schedule in schedules:
            if schedule.status in {"paid", "settled", "cancelled"}:
                continue

            alloc_fees = min(schedule.fees_due, remaining)
            schedule.paid_fees += alloc_fees
            remaining -= alloc_fees

            alloc_interest = min(schedule.interest_due, remaining)
            schedule.paid_interest += alloc_interest
            remaining -= alloc_interest

            alloc_principal = min(schedule.principal_due, remaining)
            schedule.paid_principal += alloc_principal
            remaining -= alloc_principal

            if alloc_fees > 0 or alloc_interest > 0 or alloc_principal > 0:
                db.session.add(PaymentAllocation(
                    payment_id=payment.id,
                    schedule_id=schedule.id,
                    principal=alloc_principal,
                    interest=alloc_interest,
                    fees=alloc_fees
                ))

            if schedule.paid_amount >= schedule.expected_amount:
                schedule.status = "paid"

            schedule_updated = True

            app.logger.info(
                f"[{self.loan_number}] Schedule {schedule.id} updated → fees={schedule.paid_fees}, "
                f"interest={schedule.paid_interest}, principal={schedule.paid_principal}"
            )

            if remaining <= 0:
                break

        if schedule_updated:
            self.recalculate_balance()

        if remaining > 0:
            self.record_loan_credit(payment, remaining)
        elif any(
            s.status != "paid" and (s.fees_due > 0 or s.interest_due > 0 or s.principal_due > 0)
            for s in self.repayment_schedules
        ):
            self.record_arrears(payment)

        app.logger.info(f"[{self.loan_number}] Payment of {payment.amount} allocated. Remaining: {remaining}")


    def record_loan_credit(self, payment, amount: float):
        """
        Store a loan credit when an overpayment occurs.
        This is not applied or refunded yet — pending approval or further action.
        """
        if amount <= 0:
            raise ValueError("Credit amount must be positive")

        credit = LoanCredit(
            loan=self,
            amount=round(amount, 2),
            created_at=datetime.utcnow()
            # Optionally link to payment if your model allows
        )

        db.session.add(credit)
        print(f"[{self.loan_number}] Overpayment of {amount} stored as loan credit (ID will be set on flush).")

    def expected_payment_due(self):
        """
        Total due amount across all unpaid schedules.
        Includes fees, interest, and principal.
        """
        total_due = 0.0
        for schedule in self.repayment_schedules:
            if schedule.status != 'paid':
                total_due += (
                    (schedule.fees_due - schedule.paid_fees) +
                    (schedule.interest_due - schedule.paid_interest) +
                    (schedule.principal_due - schedule.paid_principal)
                )
        return round(total_due, 2)

    def record_arrears(self, payment):
        """
        Create or update arrears if payment is insufficient.
        """
        for schedule in self.repayment_schedules:
            if schedule.status == 'paid' or schedule.due_date >= date.today():
                continue

            existing = Arrear.query.filter_by(schedule_id=schedule.id).first()

            if not existing:
                # New arrear
                arrear = Arrear(
                    loan_id=self.id,
                    schedule_id=schedule.id,
                    due_date=schedule.due_date,
                    expected_principal=schedule.expected_principal,
                    expected_interest=schedule.expected_interest,
                    expected_fees=schedule.expected_fees,
                    paid_principal=schedule.paid_principal,
                    paid_interest=schedule.paid_interest,
                    paid_fees=schedule.paid_fees,
                    status='unresolved'
                )
                db.session.add(arrear)
            else:
                # Update partial arrear
                existing.paid_principal = schedule.paid_principal
                existing.paid_interest = schedule.paid_interest
                existing.paid_fees = schedule.paid_fees
                existing.recorded_at = datetime.utcnow()

                if existing.total_arrears <= 0:
                    existing.status = 'resolved'

from app import db, app


from datetime import date

class Vote(db.Model):
    __tablename__ = 'votes'
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(10), unique=True, nullable=False)
    description = db.Column(db.String(200), nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    
    def __repr__(self):
        return f'<Vote {self.code}: {self.description}>'



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
        instalment_no = db.Column(db.Integer) 
        due_date = db.Column(db.Date)
        expected_amount = db.Column(db.Float)
        expected_principal = db.Column(db.Float)
        expected_interest = db.Column(db.Float)
        expected_fees = db.Column(db.Float)
        status = db.Column(db.String(20))
        paid_principal = db.Column(db.Float, default=0.0)
        paid_interest = db.Column(db.Float, default=0.0)
        paid_fees = db.Column(db.Float, default=0.0)
        remaining_balance = db.Column(db.Float, default=0.0) 
        status = db.Column(db.String(20), default='pending')
        arrears_amount = db.Column(db.Float, default=0.0)
        

        loan = db.relationship(
        "LoanApplication",
        back_populates="repayment_schedules",
        foreign_keys=[loan_id]
    )
        
        @property
        def arrears_days(self):
            if self.due_date < date.today() and self.status != 'paid':
                return (date.today() - self.due_date).days
            return 0
        
        @property
        def paid_amount(self):
            return self.paid_principal + self.paid_interest + self.paid_fees
       
        @property
        def fees_due(self):
            return self.expected_fees - self.paid_fees

        @property
        def interest_due(self):
            return self.expected_interest - self.paid_interest

        @property
        def principal_due(self):
            return self.expected_principal - self.paid_principal

        @property
        def due_amount(self):
            principal_due = (self.expected_principal or 0.0) - (self.paid_principal or 0.0)
            interest_due = (self.expected_interest or 0.0) - (self.paid_interest or 0.0)
            fees_due = (self.expected_fees or 0.0) - (self.paid_fees or 0.0)
            
            return max(0.0, principal_due + interest_due + fees_due)
  
        
class LoanCredit(db.Model):
    __tablename__ = 'loan_credits'
    id = db.Column(db.Integer, primary_key=True)
    loan_id = db.Column(db.Integer, db.ForeignKey('loan_applications.id'))
    amount = db.Column(db.Float, default=0.0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    applied_at = db.Column(db.DateTime, nullable=True)
    refunded_at = db.Column(db.DateTime, nullable=True)
    
    loan = db.relationship('LoanApplication', backref='credits')

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
    is_allocated = db.Column(db.Boolean, default=False)
    # Relationships
    loan = db.relationship('LoanApplication', back_populates='payments')
   
    allocations = db.relationship(
        'PaymentAllocation',
        back_populates='payment',
        cascade='all, delete-orphan'
    )

    


from sqlalchemy.orm.session import object_session
from sqlalchemy.orm import Session
from sqlalchemy import event

@event.listens_for(Session, "after_commit")
def allocate_after_commit(session):
    try:
        for obj in session.new:
            if isinstance(obj, Payment):
                app.logger.info(f"✅ Allocating after commit: Payment ID {obj.id}")
                new_session = None
                try:
                    new_session = Session(bind=session.bind)
                    # Eagerly load the loan relationship
                    payment = new_session.query(Payment).options(
                        db.joinedload(Payment.loan)
                    ).get(obj.id)

                    if not payment:
                        app.logger.warning(f"⚠️ Payment ID {obj.id} not found.")
                        continue

                    if not payment.loan:
                        app.logger.warning(f"⚠️ Loan not found for Payment ID {obj.id}")
                        continue

                    loan = payment.loan  # ✅ Now it's safe
                    PaymentAllocator(payment).process()
                    loan.recalculate_balance()

                    new_session.commit()

                except Exception as inner_error:
                    app.logger.error(
                        f"❌ Error processing Payment ID {obj.id}: {inner_error}",
                        exc_info=True
                    )
                    if new_session:
                        new_session.rollback()
                finally:
                    if new_session:
                        new_session.close()

    except Exception as e:
        app.logger.error(f"❌ Error in after_commit outer block: {e}", exc_info=True)



import math



def calculate_irr_schedule(principal: float, interest_rate: float, 
                          term_months: int, start_date: date) -> list:
    """
    Generates an IRR-based amortization schedule
    """
    monthly_rate = interest_rate
    monthly_payment = principal * (monthly_rate * (1 + monthly_rate)**term_months) / \
                      ((1 + monthly_rate)**term_months - 1)
    
    balance = principal
    schedule = []
    
    for i in range(1, term_months + 1):
        interest = balance * monthly_rate
        principal_component = monthly_payment - interest
        balance -= principal_component
        
        schedule.append({
            'due_date': start_date + relativedelta(months=i),
            'total_payment': monthly_payment,
            'principal': principal_component,
            'interest': interest,
            'balance': balance
        })
    
    return schedule

    # Helper methods would be implemented below...
    # _get_overdue_schedules, _get_current_schedule, etc.
class PaymentAllocation(db.Model):
    __tablename__ = 'payment_allocations'

    id = db.Column(db.Integer, primary_key=True)
    payment_id = db.Column(db.Integer, db.ForeignKey('payments.id'), nullable=False)

    principal = db.Column(db.Float, nullable=False)
    interest = db.Column(db.Float, nullable=False)
    settlement_interest = db.Column(db.Float, default=0.0)
    fees = db.Column(db.Float, nullable=False)

    schedule_id = db.Column(db.Integer, db.ForeignKey('repayment_schedules.id'), nullable=True)  # Keep this once only

    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    # Remove unique constraint on payment_id to allow multiple allocations per payment
    # __table_args__ = (
    #     db.UniqueConstraint('payment_id', name='uq_payment_allocation_payment_id'),
    # )

    # Relationships
    payment = db.relationship('Payment', back_populates='allocations')  # plural
    schedule = db.relationship(
        'RepaymentSchedule',
        primaryjoin='PaymentAllocation.schedule_id == RepaymentSchedule.id',
        foreign_keys=[schedule_id],
        backref='allocations'
    )

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

class Arrear(db.Model):
    __tablename__ = 'arrears'

    id = db.Column(db.Integer, primary_key=True)
    loan_id = db.Column(db.Integer, db.ForeignKey('loan_applications.id'), nullable=False)
    schedule_id = db.Column(db.Integer, db.ForeignKey('repayment_schedules.id'), nullable=True)
    
    due_date = db.Column(db.Date, nullable=False)
    recorded_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    expected_principal = db.Column(db.Float, default=0.0)
    expected_interest = db.Column(db.Float, default=0.0)
    expected_fees = db.Column(db.Float, default=0.0)

    paid_principal = db.Column(db.Float, default=0.0)
    paid_interest = db.Column(db.Float, default=0.0)
    paid_fees = db.Column(db.Float, default=0.0)
    payment_status = db.Column(db.String(20), default='pending')
    status = db.Column(db.String(20), default='unresolved')  # unresolved, resolved

    __table_args__ = (
    db.Index('ix_loan_schedule', 'loan_id', 'schedule_id'),
    )

    loan = db.relationship("LoanApplication", backref="arrears")
    schedule = db.relationship("RepaymentSchedule", backref="arrears")


    @property
    def total_due(self):
        return self.expected_principal + self.expected_interest + self.expected_fees

    @property
    def total_paid(self):
        return self.paid_principal + self.paid_interest + self.paid_fees

    @property
    def total_arrears(self):
        return self.total_due - self.total_paid

    @property
    def is_resolved(self):
        return self.total_arrears <= 0
    
    @property
    def customer(self):
        return self.loan.customer if self.loan else None

    @property
    def is_voluntary_candidate(self):
        return self.customer.is_voluntary_retirement_candidate if self.customer else False

    @property
    def voluntary_flag_reason(self):
        customer = self.customer
        if not customer:
            return None

        flags = []
        service_years = customer.years_in_service
        age = customer.age
        if service_years is not None and service_years >= 20:
            flags.append("eligible for voluntary retirement")

        if age is not None and self.loan:
            loan_term_years = self.loan.term_months // 12
            if age + loan_term_years >= 60:
                flags.append("loan ends after retirement age")

        return ", ".join(flags) if flags else None
    
    @property
    def voluntary_flag_reason(self):
        customer = self.customer
        if not customer:
            return None

        service_years = calculate_service_years(customer.date_joined)
        age = calculate_age(customer.dob)
        retirement_age = 60
        age_at_loan_end = age + (self.loan.term_months // 12)

        flags = []
        if service_years >= 20:
            flags.append("eligible for voluntary retirement")
        if age_at_loan_end >= retirement_age:
            flags.append("loan exceeds retirement age")

        return ", ".join(flags) if flags else None

# Add after models
from datetime import datetime
from app import db
from app import PaymentAllocation, RepaymentSchedule, LoanCredit

class PaymentAllocator:
    NORMAL_METHODS = {"normal", "bank_transfer", "cash", "mobile_money", "payroll_deduction"}

    def __init__(self, payment):
        if not payment or not payment.loan:
            raise ValueError("Payment must be associated with a loan")
        
        # Normalize payment method
        self.method = (payment.method or "normal").strip().lower().replace(" ", "_")
        
        if self.method in self.NORMAL_METHODS:
            self.method = "normal"
        elif self.method == "internal_topup":
            self.method = "internal_topup"
        elif self.method == "settlement":
            self.method = "settlement"
        elif "top_up" in self.method:
            self.method = "top_up"
        else:
            raise ValueError(f"Unsupported payment method: {payment.method}")

        self.payment = payment
        self.loan = payment.loan
        self.amount = payment.amount
        self.allocations = []

    def process(self):
        self._clear_existing_allocations()
        
        if self.method == "normal":
            self._allocate_to_schedules()
        elif self.method == "internal_topup":
            self._apply_direct_principal_only(target='top_up')
        elif self.method == "settlement":
            self._apply_direct_principal_only(target='settlement')
        elif self.method == "top_up":
            self._allocate_top_up()

        self._handle_credit_or_arrears()
        self._update_loan_status()
        self._persist_allocations()

    def _clear_existing_allocations(self):
        PaymentAllocation.query.filter_by(payment_id=self.payment.id).delete()

    def _allocate_to_schedules(self):
        schedules = sorted(
            self.loan.repayment_schedules,
            key=lambda s: (s.due_date, s.instalment_no)
        )
        remaining = self.amount

        for schedule in schedules:
            if schedule.status == 'paid':
                continue

            # Get due amounts
            principal_due = schedule.principal_due
            interest_due = schedule.interest_due
            fees_due = schedule.fees_due

            # Allocation priority: fees → interest → principal
            alloc_fees = min(fees_due, remaining)
            schedule.paid_fees += alloc_fees
            remaining -= alloc_fees

            alloc_interest = min(interest_due, remaining)
            schedule.paid_interest += alloc_interest
            remaining -= alloc_interest

            alloc_principal = min(principal_due, remaining)
            schedule.paid_principal += alloc_principal
            self.loan.current_balance -= alloc_principal
            remaining -= alloc_principal

            self.allocations.append(PaymentAllocation(
                payment_id=self.payment.id,
                schedule_id=schedule.id,
                principal=alloc_principal,
                interest=alloc_interest,
                fees=alloc_fees,
                created_at=datetime.utcnow()
            ))

            # Update schedule status
            total_paid = schedule.paid_amount
            if total_paid >= schedule.expected_amount:
                schedule.status = 'paid'
            elif total_paid > 0:
                schedule.status = 'partial'
            else:
                schedule.status = 'pending'

            app.logger.info(
                f"[{self.loan.loan_number}] Schedule {schedule.id} → Paid: "
                f"fees={alloc_fees}, interest={alloc_interest}, principal={alloc_principal}"
            )

            if remaining <= 0:
                break

        self.amount = remaining

    def _apply_direct_principal_only(self, target: str):
        """Handle internal top-ups as single transactions"""
        # Get target balances
        if target == 'top_up':
            principal_balance = self.loan.top_up_balance
            interest_balance = self.loan.top_up_interest or 0.0
        else:  # settlement
            principal_balance = self.loan.current_balance
            interest_balance = self.loan.settlement_interest or 0.0

        # Calculate payment distribution
        principal_paid = min(principal_balance, self.amount)
        remaining = self.amount - principal_paid
        interest_paid = min(interest_balance, remaining)

        # Create SINGLE allocation record
        self.allocations = [PaymentAllocation(  # Use single-element list
            payment_id=self.payment.id,
            principal=principal_paid,
            interest=interest_paid if target == 'top_up' else 0.0,
            settlement_interest=interest_paid if target == 'settlement' else 0.0,
            fees=0.0,
            created_at=datetime.utcnow()
        )]

        # Update loan balances
        if target == 'top_up':
            self.loan.top_up_balance -= principal_paid
            self.loan.top_up_interest = max(0, interest_balance - interest_paid)
        else:
            self.loan.current_balance -= principal_paid
            self.loan.settlement_interest = max(0, interest_balance - interest_paid)

        # Close loan if fully paid
        if target == 'top_up' and self.loan.top_up_balance <= 0 and self.loan.top_up_interest <= 0:
            self.loan.status = 'closed'
            self.loan.loan_state = 'settled_client'
            self.loan.closure_type = 'top_up'
            self.loan.closure_date = datetime.utcnow()
            
        self.amount = 0  # Full amount applied

        
    def _close_loan(self, closure_type):
        self.loan.status = "closed"
        self.loan.loan_state = "settled_client"
        self.loan.closure_type = closure_type
        self.loan.closure_date = datetime.utcnow()
        self.loan.current_balance = 0.0
        self.loan.top_up_balance = 0.0
        self.loan.settlement_balance = 0.0
        
        # Cancel all unpaid schedules
        for schedule in self.loan.repayment_schedules:
            if schedule.status not in {"paid", "cancelled"}:
                schedule.status = "cancelled"


    def _close_loan(self, closure_type):
        self.loan.status = "closed"
        self.loan.loan_state = "settled_client"
        self.loan.closure_type = closure_type
        self.loan.closure_date = datetime.utcnow()
        
        # Cancel all unpaid schedules
        for schedule in self.loan.repayment_schedules:
            if schedule.status not in {"paid", "cancelled"}:
                schedule.status = "cancelled"
        
        app.logger.info(f"[{self.loan.loan_number}] Loan marked as closed after {closure_type}.")

    def _handle_credit_or_arrears(self):
        if self.amount > 0:
            if self.method in ['internal_topup', 'top_up']:
                self.loan.top_up_interest = (self.loan.top_up_interest or 0.0) + round(self.amount, 2)
                app.logger.info(f"[{self.loan.loan_number}] Overpayment added to top-up interest: {self.amount}")
            elif self.method == 'settlement':
                self.loan.settlement_interest = (self.loan.settlement_interest or 0.0) + round(self.amount, 2)
                app.logger.info(f"[{self.loan.loan_number}] Overpayment added to settlement interest: {self.amount}")
            else:
                db.session.add(LoanCredit(
                    loan_id=self.loan.id,
                    amount=round(self.amount, 2),
                    created_at=datetime.utcnow()
                ))
                app.logger.info(f"[{self.loan.loan_number}] Overpayment recorded as loan credit: {self.amount}")
        elif any(s.status != "paid" and s.due_amount > 0 for s in self.loan.repayment_schedules):
            self.loan.record_arrears(self.payment)
            app.logger.info(f"[{self.loan.loan_number}] Underpayment detected; arrears recorded.")

    def _update_loan_status(self):
        self.loan.recalculate_balance()
        
        # Update performance status
        ARREARS_DELINQUENT = 30
        ARREARS_DEFAULT = 60
        
        if self.loan.total_arrears > ARREARS_DEFAULT:
            self.loan.performance_status = 'default'
        elif self.loan.total_arrears > ARREARS_DELINQUENT:
            self.loan.performance_status = 'delinquent'
        else:
            self.loan.performance_status = 'performing'

    def _persist_allocations(self):
        for alloc in self.allocations:
            db.session.add(alloc)
                        
def backfill_schedule_ids():
    allocations = PaymentAllocation.query.filter_by(schedule_id=None).all()
    print(f"Found {len(allocations)} allocations to backfill.")

    for alloc in allocations:
        payment = alloc.payment
        loan = payment.loan if payment else None

        if not loan or not payment:
            print(f"Skipping allocation {alloc.id}: missing loan or payment.")
            continue

        # Find first unpaid or partially paid schedule
        unpaid_schedule = next((
            s for s in sorted(loan.repayment_schedules, key=lambda r: r.due_date)
            if s.paid_amount < s.expected_amount
        ), None)

        if unpaid_schedule:
            alloc.schedule_id = unpaid_schedule.id
        else:
            print(f"No unpaid schedule found for allocation {alloc.id} (Loan ID {loan.id}).")

    db.session.commit()
    print("✅ Schedule ID backfill complete.")

# In LoanApplication model
def create_loan():
    try:
        requested_amount = float(request.form.get('requested_amount'))
        if requested_amount <= 0:
            raise ValueError("Amount must be positive")
    except (ValueError, TypeError):
        flash("Invalid requested amount", "danger")
        return redirect(url_for('loan_application_form'))

    try:
        term_months = int(request.form.get('term_months'))
        category = request.form.get('category')
        if not category:
            flash("Category is required", "danger")
            return redirect(url_for('loan_application_form'))
    except (ValueError, TypeError):
        flash("Invalid term or category", "danger")
        return redirect(url_for('loan_application_form'))

    # ✅ FIX: Use a dummy loan only for config lookup
    dummy_loan = LoanApplication(category=category, term_months=term_months)
    config = get_pricing_config(category, term_months, dummy_loan)
    if not config:
        flash("Pricing configuration not found", "danger")
        return redirect(url_for('loan_application_form'))

    # Fee calculations
    orig_fee = requested_amount * config['origination']
    ins_fee = requested_amount * config['insurance']
    crb_fee = config['crb']
    capitalized_fees = orig_fee + ins_fee + crb_fee
    loan_amount = requested_amount + capitalized_fees

    # ✅ Now create the actual loan safely
    loan = LoanApplication(
        loan_amount=round(loan_amount, 2),
        term_months=term_months,
        crb_fees=round(crb_fee, 2),
        origination_fees=round(orig_fee, 2),
        insurance_fees=round(ins_fee, 2),
        category=category,
        cash_to_client=round(requested_amount, 2),
        # Add: customer_id, file_number, etc. if required
    )

    db.session.add(loan)
    db.session.commit()

    # Optional: create disbursement
    disbursement = Disbursement(
        loan_id=loan.id,
        amount=requested_amount,
        method='bank',
        status='pending',
        reference=f"Initial disbursement for loan {loan.id}"
    )
    db.session.add(disbursement)
    db.session.commit()

    return loan




# Add this function
def generate_repayment_schedule(loan):
    # Clear existing
    for s in loan.repayment_schedules:
        db.session.delete(s)
    
    config = get_pricing_config(loan.category, loan.term_months, loan)
    if not config:
        raise ValueError(f"No pricing config for {loan.term_months} months")
    
    # Calculate components
    loan_amount = loan.loan_amount
    monthly_rate = config['rate']
    collection_fee = loan_amount * config['collection']
    
    # Capitalized amount
    capitalized = (
        loan_amount
        + (loan_amount * config['origination'])
        + (loan_amount * config['insurance'])
        + config['crb']
    )
    
    # Calculate annuity payment
    if monthly_rate > 0 and loan.term_months > 0:
        annuity_factor = (monthly_rate * (1 + monthly_rate) ** loan.term_months) / \
                         ((1 + monthly_rate) ** loan.term_months - 1)
        annuity_payment = capitalized * annuity_factor
    else:
        annuity_payment = capitalized / loan.term_months
    
    # Generate schedule
    start_date = loan.disbursement_date or datetime.utcnow().date()
    balance = capitalized
    
    for i in range(1, loan.term_months + 1):
        due_date = start_date + relativedelta(months=i)
        
        # Calculate components
        interest = balance * monthly_rate
        principal = annuity_payment - interest
        
        # Adjust last payment
        if i == loan.term_months:
            principal = balance
            annuity_payment = principal + interest
        
        # Update balance
        balance -= principal
        
        # Create schedule
        schedule = RepaymentSchedule(
            loan_id=loan.id,
            due_date=due_date,
            expected_principal=round(principal, 2),
            expected_interest=round(interest, 2),
            expected_fees=round(collection_fee, 2),
            expected_amount=round(annuity_payment + collection_fee, 2),
            status='pending'
        )
        db.session.add(schedule)
    
    # Set total fees
    loan.outstanding_fees = collection_fee * loan.term_months

# Update disbursement route

from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, BooleanField, SubmitField
from wtforms.validators import DataRequired, Length, Optional

class VoteForm(FlaskForm):
    code = StringField('Vote Code', validators=[
        DataRequired(message='Vote code is required'),
        Length(min=2, max=10, message='Code must be between 2-10 characters')
    ])
    
    description = TextAreaField('Description', validators=[
        DataRequired(message='Description is required'),
        Length(max=200, message='Description cannot exceed 200 characters')
    ])
    
    is_active = BooleanField('Active', default=True, validators=[Optional()])
    
    submit = SubmitField('Save')

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

import os
from flask.cli import with_appcontext
import click
from app import db, User
from dotenv import load_dotenv
import os
import click
from flask.cli import with_appcontext



@click.command("create-admin")
@with_appcontext
def create_admin():
    from dotenv import load_dotenv
    load_dotenv()  # Ensure latest values
    
    email = os.getenv("ADMIN_EMAIL")
    password = os.getenv("ADMIN_PASSWORD")
    
    if not email or not password:
        raise click.ClickException("ADMIN_EMAIL and ADMIN_PASSWORD must be set")

    essential_perms = [
        ('*', '*'),  # Wildcard
        ('loan', 'create'),
        ('loan', 'approve'),
        ('loan', 'view'),
        ('user', 'manage'),
        # Add other essential permissions
    ]
    
    # 1. Ensure essential permissions exist
    for res, action in essential_perms:
        perm = Permission.query.filter_by(resource=res, action=action).first()
        if not perm:
            perm = Permission(resource=res, action=action)
            db.session.add(perm)
    
    # 2. Create admin role with all permissions
    admin_role = Role.query.filter_by(name='admin').first()
    if not admin_role:
        admin_role = Role(name='admin')
        db.session.add(admin_role)
        db.session.commit()  # Need ID for relationship
        
        # Assign all permissions to admin role
        all_perms = Permission.query.all()
        for perm in all_perms:
            admin_role.permissions.append(perm)
    
        db.session.commit()
        
    # 3. Create or update admin user
    existing = User.query.filter_by(email=email).first()
    if existing:
        # Update existing user to admin
        existing.username = 'admin'  # <-- Ensure username is set!
        existing.role_id = admin_role.id
        existing.set_password(password)
        db.session.commit()
        click.echo(f"🛡️ User promoted to admin: {email} (username: admin)")
    else:
        # Create new admin
        admin = User(
            email=email,
            username='admin',  # <-- Set username here!
            role_id=admin_role.id,
        )
        admin.set_password(password)
        db.session.add(admin)
        db.session.commit()
        click.echo(f"✅ Admin created: {email} (username: admin)")

def register_cli_commands(app):
    app.cli.add_command(create_admin)

# Register CLI commands
register_cli_commands(app)

    
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

from datetime import date

def calculate_age(dob):
    if not dob:
        return 0
    today = date.today()
    return today.year - dob.year - ((today.month, today.day) < (dob.month, dob.day))

def calculate_service_years(joined_date):
    if not joined_date:
        return 0
    today = date.today()
    return today.year - joined_date.year - ((today.month, today.day) < (joined_date.month, joined_date.day))



def get_voluntary_retirement_loan_alerts():
    today = date.today()

    return Arrear.query.join(LoanApplication).join(Customer).filter(
        LoanApplication.loan_state == 'active',
        Customer.is_voluntary_retirement_candidate == True,
        Arrear.payment_status != 'cleared',  # Optional, based on how you define "arrears"
        Arrear.total_arrears > 0
    ).all()

@app.route('/alerts/voluntary-retirement')
def voluntary_retirement_alerts():
    arrears = get_voluntary_retirement_loan_alerts()
    results = [{
        'customer': f"{a.customer.first_name} {a.customer.last_name}",
        'file_number': a.loan.file_number,
        'reason': a.voluntary_flag_reason,
        'total_arrears': a.total_arrears,
    } for a in arrears]

    return jsonify(results)


# app.py  (excerpt)
from flask import request, abort, render_template
from flask_login import login_required, current_user

@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    if current_user.role.name != 'admin':
        abort(403)
    
    # Moved to top: Get section parameter first with default value
    section = request.args.get('section', 'users')  # Default to 'users'

    cutoff_configs = {
        c.category: c.cutoff_dt
        for c in CutoffDateConfig.query.all()
    }

    if section == 'cutoff_dates':
        civil_config = CutoffDateConfig.query.filter_by(category='civil_servant').first()
        private_config = CutoffDateConfig.query.filter_by(category='private_sector').first()
        cutoff_configs = {
            'civil_servant': civil_config.cutoff_dt if civil_config else '',
            'private_sector': private_config.cutoff_dt if private_config else ''
        }
        return render_template(
            'admin_dashboard.html',
            section=section,
            cutoff_configs=cutoff_configs,
            users=[],
            roles=[],
            configs_by_category={},
            categories=[],
            terms=[]
        )

    if section == 'pricing':
        # Create initial pricing configurations if none exist
        if not PricingConfig.query.first():
            create_initial_pricing_configs()
        
        # Get all configurations grouped by category
        configs = PricingConfig.query.order_by(
            PricingConfig.category, 
            PricingConfig.term_months
        ).all()
        
        configs_by_category = {}
        for config in configs:
            if config.category not in configs_by_category:
                configs_by_category[config.category] = []
            configs_by_category[config.category].append(config)
        
        return render_template(
            'admin_dashboard.html',
            section=section,
            categories=['civil_servant', 'private_sector', 'sme'],
            terms=[3, 6, 9, 12, 18, 24, 36, 48],
            configs_by_category=configs_by_category,
            users=[],  # Added for template consistency
            roles=[]   # Added for template consistency
        )

    # Non-pricing section (default: 'users')
    users = User.query.all()
    roles = Role.query.all()
    return render_template(
        'admin_dashboard.html',
        users=users,
        roles=roles,
        section=section,
        cutoff_configs=cutoff_configs,
        configs_by_category={},
        categories=[],
        terms=[]
    )

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




# ... existing imports ...

# Add this route to your app.py
@app.route('/admin/pricing', methods=['GET', 'POST'])
@login_required
@role_required('admin', 'finance_officer')
def admin_pricing():
    # Create initial pricing configurations if none exist
    if not PricingConfig.query.first():
        create_initial_pricing_configs()
    
    if request.method == 'POST':
        category = request.form['category']
        term = int(request.form['term'])
        
        config = PricingConfig.query.filter_by(
            category=category,
            term_months=term
        ).first()
        
        if not config:
            config = PricingConfig(
                category=category,
                term_months=term
            )
        
        config.interest_rate = float(request.form['interest_rate'])
        config.origination_fee = float(request.form['origination_fee'])
        config.insurance_fee = float(request.form['insurance_fee'])
        config.collection_fee = float(request.form['collection_fee'])
        config.crb_fee = float(request.form['crb_fee'])
        
        # Application scope fields
        config.apply_to_new = 'apply_to_new' in request.form
        config.apply_to_existing = 'apply_to_existing' in request.form
        config.apply_interest_to_existing = 'apply_interest_to_existing' in request.form
        config.apply_collection_to_existing = 'apply_collection_to_existing' in request.form
        
        db.session.add(config)
        db.session.commit()
        
        # Apply changes to existing loans if requested
        if config.apply_to_existing:
            apply_pricing_to_existing_loans(config)
            
        flash('Pricing configuration saved', 'success')
        return redirect(url_for('admin_pricing'))
    
    # GET request handling
    configs = PricingConfig.query.order_by(
        PricingConfig.category, 
        PricingConfig.term_months
    ).all()
    
    configs_by_category = {}
    for config in configs:
        if config.category not in configs_by_category:
            configs_by_category[config.category] = []
        configs_by_category[config.category].append(config)
    
    return render_template(
        'admin_pricing.html',
        categories=['civil_servant', 'private_sector', 'sme'],
        terms=[3, 6, 9, 12, 18, 24, 36, 48],
        configs_by_category=configs_by_category
    )

def create_initial_pricing_configs():
    """Create default pricing configurations if none exist"""
    terms = [3, 6, 9, 12, 18, 24, 36, 48]
    categories = ['civil_servant', 'private_sector', 'sme']
    
    # Default values based on your PRICING dictionary
    for category in categories:
        for term in terms:
            pricing_data = PRICING.get(term, {
                'rate': 0.035,
                'origination': 0.15,
                'insurance': 0.026,
                'collection': 0.0025,
                'crb': 3000
            })
            
            config = PricingConfig(
                category=category,
                term_months=term,
                interest_rate=pricing_data['rate'],
                origination_fee=pricing_data['origination'],
                insurance_fee=pricing_data['insurance'],
                collection_fee=pricing_data['collection'],
                crb_fee=pricing_data['crb']
            )
            db.session.add(config)
    
    db.session.commit()

def apply_pricing_to_existing_loans(config):
    """Apply pricing changes to existing loans based on configuration"""
    from sqlalchemy import and_
    
    query = LoanApplication.query.filter(
        and_(
            LoanApplication.category == config.category,
            LoanApplication.term_months == config.term_months,
            LoanApplication.loan_state == 'active'
        )
    )
    
    for loan in query.all():
        updated = False
        
        # Update interest rate if requested
        if config.apply_interest_to_existing:
            loan.applied_interest_rate = config.interest_rate
            updated = True
        
        # Update collection fee if requested
        if config.apply_collection_to_existing:
            loan.applied_collection_fee = config.collection_fee
            updated = True
        
        # Regenerate schedule if any rate changed
        if updated:
            loan.pricing_version += 1
            loan.generate_repayment_schedule()
    
    db.session.commit()

# Add this helper function to your utils
def get_pricing_config(category, term_months, loan=None):
    # For existing loans, use the applied rates if available
    if loan and loan.applied_interest_rate is not None:
        return {
            'rate': loan.applied_interest_rate,
            'origination': loan.origination_fees / loan.loan_amount if loan.loan_amount else 0.15,
            'insurance': loan.insurance_fees / loan.loan_amount if loan.loan_amount else 0.026,
            'collection': loan.applied_collection_fee if loan.applied_collection_fee is not None else 0.0025,
            'crb': loan.crb_fees if loan.crb_fees is not None else 3000
        }
    
    # Look for active pricing config
    config = PricingConfig.query.filter_by(
        category=category,
        term_months=term_months,
        apply_to_new=True
    ).order_by(PricingConfig.updated_at.desc()).first()
    
    if config:
        return {
            'rate': config.interest_rate,
            'origination': config.origination_fee,
            'insurance': config.insurance_fee,
            'collection': config.collection_fee,
            'crb': config.crb_fee
        }
    
    # Fallback to default PRICING
    return PRICING.get(term_months, {
        'rate': 0.035,
        'origination': 0.15,
        'insurance': 0.026,
        'collection': 0.0025,
        'crb': 3000
    })    

from datetime import datetime
from sqlalchemy import func, extract

from flask_login import current_user
from sqlalchemy import and_

@app.route('/admin/cutoff_dates', methods=['POST'])
@login_required
@role_required('admin', 'finance_officer')
def manage_cutoff_dates():
    for category in ['civil_servant', 'private_sector']:
        day = request.form.get(category)
        if day:
            config = CutoffDateConfig.query.filter_by(category=category).first()
            if config:
                config.cutoff_dt = int(day)
            else:
                config = CutoffDateConfig(category=category, cutoff_dt=int(day))
                db.session.add(config)
    db.session.commit()
    flash('Cutoff dates updated successfully.', 'success')
    return redirect(url_for('admin_dashboard', section='cutoff_dates'))

@app.route('/admin/update_cutoff', methods=['POST'])
@login_required
@role_required('admin', 'finance_officer')
def update_single_cutoff():
    category   = request.form.get('category')
    cutoff_raw = request.form.get('cutoff_dt')  # e.g. '2025-07-01T15:30'
    try:
        cutoff_dt = datetime.strptime(cutoff_raw, '%Y-%m-%dT%H:%M')
    except ValueError:
        flash('Invalid date-time format.', 'danger')
        return redirect(url_for('admin_dashboard', section='cutoff_dates'))

    cfg = CutoffDateConfig.query.filter_by(category=category).first()
    if not cfg:
        cfg = CutoffDateConfig(category=category)
        db.session.add(cfg)
    cfg.cutoff_dt = cutoff_dt              # store full datetime
    db.session.commit()

    flash(f'{category.replace("_", " ").title()} cut-off updated.', 'success')
    return redirect(url_for('admin_dashboard', section='cutoff_dates'))


@app.route('/admin/votes')
@login_required
@role_required('admin')
def manage_votes():
    votes = Vote.query.order_by(Vote.code.asc()).all()
    return render_template('admin/votes.html', votes=votes)

@app.route('/admin/dashboard/votes', methods=['GET', 'POST'])
@app.route('/admin/dashboard/votes/<int:vote_id>', methods=['GET', 'POST'])
def admin_votes(vote_id=None):
    form = VoteForm()
    edit_mode = vote_id is not None
    
    if edit_mode:
        vote = Vote.query.get_or_404(vote_id)
        form = VoteForm(obj=vote)
    
    if form.validate_on_submit():
        if edit_mode:
            # Update existing vote
            vote.code = form.code.data
            vote.description = form.description.data
            vote.is_active = form.is_active.data
            db.session.commit()
            flash('Vote updated successfully!', 'success')
        else:
            # Create new vote
            vote = Vote(
                code=form.code.data,
                description=form.description.data,
                is_active=form.is_active.data
            )
            db.session.add(vote)
            db.session.commit()
            flash('Vote added successfully!', 'success')
        return redirect(url_for('admin_votes'))
    
    votes = Vote.query.order_by(Vote.code.asc()).all()
    return render_template('admin_dashboard.html',
                           section='votes',
                           form=form,
                           votes=votes,
                           edit_mode=edit_mode,
                           vote_id=vote_id)



@app.route('/admin/votes/new', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def new_vote():
    form = VoteForm()
    if form.validate_on_submit():
        vote = Vote(
            code=form.code.data,
            description=form.description.data,
            is_active=form.is_active.data
        )
        db.session.add(vote)
        db.session.commit()
        flash('Vote added successfully!', 'success')
        return redirect(url_for('manage_votes'))
    return render_template('admin/vote_form.html', form=form, title='Add New Vote')

@app.route('/admin/votes/edit/<int:vote_id>', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def edit_vote(vote_id):
    vote = Vote.query.get_or_404(vote_id)
    form = VoteForm(obj=vote)
    
    if form.validate_on_submit():
        vote.code = form.code.data
        vote.description = form.description.data
        vote.is_active = form.is_active.data
        db.session.commit()
        flash('Vote updated successfully!', 'success')
        return redirect(url_for('manage_votes'))
    
    return render_template('admin/vote_form.html', form=form, title='Edit Vote')

@app.route('/delete_vote/<int:vote_id>', methods=['POST'])
@login_required
@role_required('admin')
def delete_vote(vote_id):
    vote = Vote.query.get_or_404(vote_id)
    
    # Check if vote is used in any loan applications
    if LoanApplication.query.filter_by(vote_id=vote_id).count() > 0:
        flash('Cannot delete vote because it is used in loan applications!', 'danger')
        return redirect(url_for('manage_votes'))
    
    db.session.delete(vote)
    db.session.commit()
    flash('Vote deleted successfully!', 'success')
    return redirect(url_for('manage_votes'))

@app.route('/admin/votes/merge', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def merge_votes():
    if request.method == 'POST':
        source_id = request.form.get('source_vote')
        target_id = request.form.get('target_vote')
        
        if not source_id or not target_id or source_id == target_id:
            flash('Please select two different votes to merge', 'danger')
            return redirect(url_for('merge_votes'))
        
        source_vote = Vote.query.get(source_id)
        target_vote = Vote.query.get(target_id)
        
        if not source_vote or not target_vote:
            flash('Invalid vote selection', 'danger')
            return redirect(url_for('merge_votes'))
        
        # Update all loan applications using the source vote
        LoanApplication.query.filter_by(vote_id=source_id).update({LoanApplication.vote_id: target_id})
        
        # Delete the source vote
        db.session.delete(source_vote)
        db.session.commit()
        
        flash(f'Successfully merged "{source_vote.code}" into "{target_vote.code}"', 'success')
        return redirect(url_for('manage_votes'))
    
    votes = Vote.query.order_by(Vote.code.asc()).all()
    return render_template('admin/merge_votes.html', votes=votes)

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

def calculate_balances(loan):
    config = get_pricing_config(loan.category, loan.term_months, loan)
    if not config:
        return {}

    def calculate_capitalized_amount(loan_amount, config):
        try:
            origination = loan_amount * config.get('origination', 0)
            insurance = loan_amount * config.get('insurance', 0)
            crb = config.get('crb', 0)
            return round(loan_amount + origination + insurance + crb, 2)
        except Exception as e:
            app.logger.warning(f"Capitalization error: {e}")
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

    # Define valid statuses:
    VALID_PAYMENT_STATUSES = ('successful', 'completed')
    INVALID_PAYMENT_STATUSES = ('failed', 'reversed', 'cancelled')

    for p in payments:
        payment_status = getattr(p, 'status', '').lower()
        payment_method = getattr(p, 'method', '').lower()

        # Skip invalid payments
        if payment_status in INVALID_PAYMENT_STATUSES:
            continue

        # For computing remaining_balance — count all valid principal allocations:
        if p.allocation and p.allocation.principal:
            remaining_balance -= p.allocation.principal
            remaining_balance = max(remaining_balance, 0)
            payments_made += 1

    current_balance = round(remaining_balance, 2)
    remaining_term = max(term - payments_made, 0)

    # Projected interest
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

    top_up_interest = projected_interest(3)
    settlement_interest = projected_interest(6)

    return {
        'capitalized_amount': capitalized,
        'current_balance': current_balance,
        'top_up_balance': round(current_balance + top_up_interest, 2),
        'settlement_balance': round(current_balance + settlement_interest, 2),
        'top_up_interest': top_up_interest,
        'settlement_interest': settlement_interest,
    }


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
            config = get_pricing_config(loan.category, loan.term_months, loan)
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
                for allocation in p.allocations:
                    if allocation.principal:
                        remaining_balance -= allocation.principal
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

from datetime import date

@app.route('/loan/<loan_number>/statement')
def loan_statement(loan_number):
    try:
        loan = (LoanApplication.query
                .options(
                    db.joinedload(LoanApplication.customer),
                    db.joinedload(LoanApplication.payments)
                        .joinedload(Payment.allocations)
                )
                .filter_by(loan_number=loan_number)
                .first_or_404())

        config = get_pricing_config(loan.category, loan.term_months, loan)
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
            for allocation in payment.allocations:
                if allocation.principal:
                    running_balance -= allocation.principal
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
            for allocation in payment.allocations:
                running_balance_display -= allocation.principal or 0
                allocated_total = (allocation.principal or 0) + (allocation.interest or 0) + (allocation.fees or 0)
                valid_allocation = abs(allocated_total - payment.amount) < 0.01
                statement.append({
                    'id': payment.id,
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
            'principal': sum(a.principal for p in loan.payments for a in p.allocations),
            'interest': sum(a.interest for p in loan.payments for a in p.allocations),
            'fees': sum(a.fees for p in loan.payments for a in p.allocations)
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
            date=date,
            totals=totals
        )
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
@app.cli.command("init-pricing")
def init_pricing():
    """Create initial pricing configurations"""
    terms = [3, 6, 9, 12, 18, 24, 36, 48]
    categories = ['civil_servant', 'private_sector', 'sme']
    
    for category in categories:
        for term in terms:
            pricing_data = PRICING.get(term, {
                'rate': 0.035,
                'origination': 0.15,
                'insurance': 0.026,
                'collection': 0.0025,
                'crb': 3000
            })
            
            if not PricingConfig.query.filter_by(category=category, term_months=term).first():
                config = PricingConfig(
                    category=category,
                    term_months=term,
                    interest_rate=pricing_data['rate'],
                    origination_fee=pricing_data['origination'],
                    insurance_fee=pricing_data['insurance'],
                    collection_fee=pricing_data['collection'],
                    crb_fee=pricing_data['crb']
                )
                db.session.add(config)
    
    db.session.commit()
    print("Initial pricing configurations created")

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

    config = get_pricing_config(category, term_months)
    if not config:
        raise Exception("Invalid loan term selected.")

    # Validate Date of Birth
    dob = datetime.strptime(data['dob'], "%Y-%m-%d").date()
    today = date.today()
    age = today.year - dob.year - ((today.month, today.day) < (dob.month, dob.day))
    if age < 16:
        raise Exception("Customer must be at least 16 years old.")

    # Validate and parse date joined
    date_joined = data.get("date_joined")
    if date_joined:
        date_joined = datetime.strptime(date_joined, "%Y-%m-%d").date()
        years_in_service = today.year - date_joined.year - ((today.month, today.day) < (date_joined.month, date_joined.day))
        if years_in_service >= 20:
            flash("⚠️ Customer is eligible for voluntary retirement (20+ years in service)", "warning")
    else:
        years_in_service = None

    # Check for retirement age at loan completion
    if age + (term_months // 12) > 60:
        raise Exception("Loan tenure will exceed retirement age (60 years).")

    # Pricing
    crb_fees = 3000
    origination_fees = loan_amount * config['origination']
    insurance_fees = loan_amount * config['insurance']
    collection_fees = loan_amount * config['collection']
    capitalized_amount = loan_amount + origination_fees + insurance_fees + crb_fees

    annuity_factor = (config['rate'] * (1 + config['rate']) ** term_months) / \
                     ((1 + config['rate']) ** term_months - 1)
    monthly_instalment = (capitalized_amount * annuity_factor) + collection_fees

    # Check for duplicates
    if Customer.query.filter_by(email=data['email']).first():
        raise Exception("Email already exists.")
    if Customer.query.filter_by(national_id=data['national_id']).first():
        raise Exception("National ID already exists.")

    # Generate file number
    now = datetime.utcnow()
    customer_count = db.session.query(Customer).count()
    file_sequence = str(customer_count + 1).zfill(6)
    file_number = f"{now.year}{str(now.month).zfill(2)}{file_sequence}"

    # Create customer
    customer = Customer(
        national_id=data['national_id'],
        first_name=data['first_name'],
        last_name=data['last_name'],
        gender=data.get('gender'),
        dob=dob,
        date_joined=date_joined,
        title=data.get('title'),
        email=data['email'],
        contact=data.get('contact'),
        address=data.get('address'),
        employer=data['employer'],
        job_title=data.get('job_title'),
        salary=float(data.get('salary') or 0),
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

    # Upload documents
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

    # Loan logic
    tenure = str(term_months).zfill(2)
    loan_count = db.session.query(LoanApplication).count()
    loan_sequence = str(loan_count + 1).zfill(6)
    loan_number = f"{prefix}{tenure}{loan_sequence}"

    previous_loan = LoanApplication.query.filter_by(customer_id=customer.id).order_by(LoanApplication.id.desc()).first()
    top_up_balance = 0
    if previous_loan and previous_loan.loan_state in ['active', 'closed']:
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
        cash_to_client=round(cash_to_client, 2),
        applied_interest_rate=config['rate'],
        applied_collection_fee=config['collection']
    )

    db.session.add(loan)
    db.session.flush()

    loan.generate_repayment_schedule()

    disbursement = Disbursement(
        loan_id=loan.id,
        amount=cash_to_client,
        method='bank',
        status='pending',
        reference=f"Initial disbursement for {loan.loan_number}"
    )
    db.session.add(disbursement)

    db.session.commit()




@app.route('/customers')
def customers():
    approved_customers = Customer.query.filter_by(is_approved_for_creation=True).all()
    return render_template('customers_list.html', customers=approved_customers)

@app.route('/approve_customers', methods=['GET', 'POST'])
@login_required
def approve_customers():
    if request.method == 'POST':
        selected_ids = request.form.getlist('customer_ids')
        
        if selected_ids:
            customers = Customer.query.filter(Customer.id.in_(selected_ids)).all()
            approved_count = 0
            
            for customer in customers:
                vote_id = request.form.get(f'vote_{customer.id}')
                
                if not vote_id:
                    flash(f"No vote selected for {customer.first_name} {customer.last_name}", "warning")
                    continue
                
                vote = Vote.query.get(vote_id)
                if not vote:
                    flash(f"Invalid vote selected for {customer.first_name} {customer.last_name}", "danger")
                    continue
                
                customer.is_approved_for_creation = True
                customer.checker_id = current_user.id
                
                if not customer.loans:
                    loan = LoanApplication(
                        customer_id=customer.id,
                        loan_amount=customer.amount_requested or 0.0,
                        loan_category="SME",
                        status='pending',
                        loan_state='Active',
                        application_status='awaiting_approval',
                        vote_id=vote.id
                    )
                    db.session.add(loan)
                    approved_count += 1
                else:
                    for loan in customer.loans:
                        loan.status = 'pending'
                        loan.vote_id = vote.id
                    approved_count += 1
            
            db.session.commit()
            flash(f"{approved_count} customer(s) approved with vote assignments!", "success")
        else:
            flash("No customers selected.", "warning")
        return redirect(url_for('approve_customers'))
    
    # GET request handling
    unapproved_customers = Customer.query.filter_by(is_approved_for_creation=False).all()
    
    # Get all active votes (fallback to all votes if none active)
    active_votes = Vote.query.filter_by(is_active=True).order_by(Vote.code.asc()).all()
    if not active_votes:
        active_votes = Vote.query.order_by(Vote.code.asc()).all()
    
    # Normalize amount_requested
    for customer in unapproved_customers:
        try:
            customer.amount_requested = float(customer.amount_requested)
        except (TypeError, ValueError):
            customer.amount_requested = 0.0
    
    return render_template(
        'approve_customers.html', 
        customers=unapproved_customers,
        votes=active_votes
    )

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
    loans = (
        LoanApplication.query
        .join(Customer)
        .filter(Customer.is_approved_for_creation.is_(True))
        .filter(LoanApplication.status.in_(['pending', 'approved']))
        .options(joinedload(LoanApplication.documents))  # <-- eager‑load docs
        .add_entity(Customer)
        .all()
    )

    processed_loans = [
        {
            "loan":      loan_app,
            "customer":  customer,
            "current_balance": loan_app.balance or 0.0,
        }
        for loan_app, customer in loans
    ]

    return render_template("view_loans.html", loans=processed_loans)
       
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
            customer_id = int(data['customer_id'])
            term_months = int(data['loan_term'])
            loan_amount = float(data['loan_amount'])
            category = data.get('category')

            # Find the existing customer
            customer = Customer.query.get(customer_id)
            if not customer:
                flash("Customer not found.", "danger")
                return redirect(url_for('create_existing_loan'))

            # ✅ Use a dummy loan for config lookup — DO NOT use 'loan' yet
            dummy_loan = LoanApplication(category=category, term_months=term_months)
            config = get_pricing_config(category, term_months, dummy_loan)
            if not config:
                flash("Invalid loan term selected", "danger")
                return redirect(url_for('create_existing_loan'))

            # Fee calculations
            crb_fees = 3000  # Fixed CRB fee
            origination_fees = loan_amount * config['origination']
            insurance_fees = loan_amount * config['insurance']
            collection_fees = loan_amount * config['collection']
            capitalized_amount = loan_amount + origination_fees + insurance_fees + crb_fees

            annuity_factor = (config['rate'] * (1 + config['rate']) ** term_months) / \
                             ((1 + config['rate']) ** term_months - 1)
            monthly_instalment = (capitalized_amount * annuity_factor) + collection_fees

            # Generate loan + file number
            loan_number, file_number = generate_loan_and_file_number(category, term_months, db.session)

            # ✅ Now define the actual loan
            loan = LoanApplication(
                customer_id=customer.id,
                loan_amount=loan_amount,
                term_months=term_months,
                monthly_instalment=round(monthly_instalment, 2),
                total_repayment=round(monthly_instalment * term_months, 2),
                effective_rate=calculate_eir(loan_amount, term_months, config),
                category=category,
                loan_category=1,  # Adjust if needed
                status='pending',
                crb_fees=crb_fees,
                origination_fees=round(origination_fees, 2),
                insurance_fees=round(insurance_fees, 2),
                collection_fees=round(collection_fees, 2),
                loan_number=loan_number,
                file_number=file_number
            )

            db.session.add(loan)
            db.session.commit()

            flash("Loan created successfully for existing customer. Awaiting approval.", "success")
            return redirect(url_for('loanbook'))

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
@login_required
@role_required("admin", "finance_officer")
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
            .options(joinedload(LoanApplication.payments).joinedload(Payment.allocations)) \
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
                .joinedload(Payment.allocations)
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

def calculate_eir(principal, months, config, fees=None):
    """
    Calculate Effective Interest Rate (EIR) with flexible input
    Supports both regular loan creation (with config) and batch import (with fees)
    """
    # Extract rate from config
    rate = config.get('rate', 0)
    
    # Calculate total fees based on input method
    if fees is not None:
        # Use directly provided fees (batch import)
        total_fees = fees
    else:
        # Calculate fees from config (regular loan creation)
        origination_rate = config.get('origination', 0)
        insurance_rate = config.get('insurance', 0)
        crb_fee = config.get('crb', 0)
        
        origination_fees = principal * origination_rate
        insurance_fees = principal * insurance_rate
        total_fees = origination_fees + insurance_fees + crb_fee

    # Calculate total interest
    balance = principal
    total_interest = 0
    total_balances = 0

    for _ in range(months):
        interest = balance * rate
        total_interest += interest
        total_balances += balance
        balance -= principal / months  # Simple principal reduction

    # Calculate EIR
    average_balance = total_balances / months
    eir = ((total_interest + total_fees) / average_balance) * (12 / months) * 100
    
    return round(eir, 2)


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
                        normalized_row = {k.strip().lower(): v.strip() for k, v in row.items()}
                        loan_number = normalized_row.get('loan_number', '').strip()

                        if not loan_number:
                            errors.append(f"Missing loan_number in row: {row}")
                            continue

                        amount_str = normalized_row.get('amount', '').replace(',', '')
                        try:
                            amount = float(amount_str)
                        except ValueError:
                            errors.append(f"Invalid amount '{amount_str}' for loan {loan_number}")
                            continue

                        loan = LoanApplication.query.filter_by(loan_number=loan_number).first()
                        if not loan:
                            errors.append(f"Loan {loan_number} not found")
                            continue

                        payment = Payment(
                            loan_id=loan.id,
                            amount=amount,
                            method=normalized_row.get('method', 'Batch Upload'),
                            reference=normalized_row.get('reference', '')
                        )
                        db.session.add(payment)
                        db.session.flush()  # Ensure payment.id is available

                        PaymentAllocator(payment).process()
                        loan.recalculate_balance()

                        success += 1

                    except Exception as e:
                        errors.append(f"Error processing row {row}: {str(e)}")
                        continue

                db.session.commit()
                flash(f"Processed {success} payments, {len(errors)} errors", 'info')
                if errors:
                    flash('First 5 errors: ' + ' | '.join(errors[:5]), 'warning')

            else:
                # Single payment
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
                db.session.flush()

                PaymentAllocator(payment).process()
                loan.recalculate_balance()

                db.session.commit()
                flash('Payment recorded successfully', 'success')

        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Payment error: {str(e)}", exc_info=True)
            flash(f'Payment failed: {str(e)}', 'danger')

        return redirect(url_for('payments'))

    # GET method
    loan_number = request.args.get('loan_number')
    if loan_number:
        loan = LoanApplication.query.filter_by(loan_number=loan_number).first()

    return render_template('payments.html', loan=loan)



@app.route('/payment/<int:payment_id>/edit', methods=['GET', 'POST'])
@login_required
@role_required('finance_officer', 'admin')
def edit_payment(payment_id):
    payment = Payment.query.get_or_404(payment_id)
    loan = payment.loan

    if request.method == 'POST':
        try:
            new_amount = float(request.form['amount'])
            if new_amount <= 0:
                flash("Amount must be positive", "danger")
                return redirect(url_for('edit_payment', payment_id=payment.id))

            # Update amount
            payment.amount = new_amount

            # Re-allocate using PaymentAllocator
            db.session.flush()
            PaymentAllocator(payment).process()

            loan.recalculate_balance()
            db.session.commit()

            flash("Payment updated successfully", "success")
            return redirect(url_for('loan_statement', loan_number=loan.loan_number))

        except ValueError:
            flash("Invalid amount format", "danger")
        except Exception as e:
            db.session.rollback()
            flash(f"Error updating payment: {str(e)}", "danger")

    return render_template('edit_payment.html', payment=payment, loan=loan)

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
        per_page = 1000
        ajax = request.args.get("ajax") == "true"

        loans_query = LoanApplication.query \
            .join(Customer, LoanApplication.customer_id == Customer.id) \
            .options(joinedload(LoanApplication.payments).joinedload(Payment.allocations))

        all_loans = loans_query.all()

        processed_loans = []
        for loan in all_loans:
            customer = loan.customer
            config = get_pricing_config(loan.category, loan.term_months, loan)
            loan_amount = loan.loan_amount or 0

            capitalized = (
                loan_amount
                + (loan_amount * config.get('origination', 0))
                + (loan_amount * config.get('insurance', 0))
                + config.get('crb', 0)
            )

            total_principal_paid = sum(
                (alloc.principal or 0)
                for p in loan.payments
                for alloc in p.allocations
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

def process_topup_registration(data, base_loan, loan_form=None, bank_payslip=None, live_photo=None):
    try:
        new_amount = float(data['amount_requested'])
        term_months = int(data['tenure'])
    except (ValueError, KeyError):
        raise Exception("Invalid input for loan amount or tenure.")

    category_code = base_loan.loan_category
    CATEGORY_MAP = {
        1: {'prefix': '1', 'label': 'civil_servant'},
        2: {'prefix': '2', 'label': 'private_sector'},
        3: {'prefix': '3', 'label': 'sme'}
    }

    category_info = CATEGORY_MAP.get(category_code)
    if not category_info:
        raise Exception("Unknown loan category.")

    # Use base_loan.category (label string) for pricing config lookup
    config = get_pricing_config(base_loan.category, term_months)
    if not config:
        raise Exception("Pricing configuration unavailable.")

    # --- Fees
    crb_fees = config.get('crb', 3000)
    origination_fees = new_amount * config.get('origination', 0)
    insurance_fees = new_amount * config.get('insurance', 0)
    collection_fees = new_amount * config.get('collection', 0)

    # --- Top-up Balance Calculation
    def calculate_topup_balance(loan):
        loan_config = get_pricing_config(loan.category, loan.term_months)

        def capitalized_amount(amt, cfg):
            return round(
                amt +
                (amt * cfg.get('origination', 0)) +
                (amt * cfg.get('insurance', 0)) +
                cfg.get('crb', 0),
                2
            )

        capitalized = capitalized_amount(loan.loan_amount or 0, loan_config)
        rate = loan_config.get('rate', 0)
        term = loan.term_months or 0

        annuity = (capitalized * rate * (1 + rate) ** term) / ((1 + rate) ** term - 1) if rate > 0 and term > 0 else 0

        payments = sorted(loan.payments, key=lambda p: p.created_at)
        paid_principal = sum(
            alloc.principal for p in payments for alloc in p.allocations if alloc.principal
        )

        current_balance = round(capitalized - paid_principal, 2)
        payments_made = sum(
            1 for p in payments for alloc in p.allocations if alloc.principal
        )
        remaining_term = max(term - payments_made, 0)

        interest_total = 0.0
        temp_balance = current_balance
        for _ in range(min(3, remaining_term)):
            if temp_balance <= 0:
                break
            interest = temp_balance * rate
            principal = min(annuity - interest, temp_balance)
            interest_total += interest
            temp_balance -= principal

        top_up_interest = round(interest_total, 2)
        return round(current_balance + top_up_interest, 2), top_up_interest

    top_up_balance, top_up_interest = calculate_topup_balance(base_loan)

    cash_to_client = new_amount - top_up_balance
    if cash_to_client <= 0:
        raise Exception("Requested amount too low to cover top-up of previous balance.")

    # --- Prepare New Loan
    capitalized_amount = new_amount + origination_fees + insurance_fees + crb_fees
    annuity_factor = (config['rate'] * (1 + config['rate']) ** term_months) / \
                     ((1 + config['rate']) ** term_months - 1)
    monthly_instalment = (capitalized_amount * annuity_factor) + collection_fees

    now = datetime.utcnow()
    loan_sequence = str(db.session.query(LoanApplication).count() + 1).zfill(6)
    loan_number = f"{category_info['prefix']}{str(term_months).zfill(2)}{loan_sequence}"

    # --- Create New Top-up Loan
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
        top_up_balance=top_up_balance,
        top_up_interest=top_up_interest,
        cash_to_client=round(cash_to_client, 2),
        applied_interest_rate=config['rate'],
        applied_collection_fee=config['collection'],
        date_created=now
    )

    db.session.add(topup_loan)
    db.session.flush()

    # --- Disbursement Record
    disbursement = Disbursement(
        loan_id=topup_loan.id,
        amount=cash_to_client,
        method='bank',
        status='pending',
        reference=f"Top-up disbursement for {loan_number}"
    )
    db.session.add(disbursement)

    # --- Document Uploads
    for file_obj, filetype in [
        (loan_form, 'loan_form'),
        (bank_payslip, 'bank_payslip'),
        (live_photo, 'live_photo')
    ]:
        if file_obj:
            filename, filepath = save_file(file_obj, subfolder=f"topup_loan_{topup_loan.id}")
            if filename:
                db.session.add(Document(
                    customer_id=base_loan.customer_id,
                    loan_id=topup_loan.id,
                    filename=filename,
                    filetype=filetype,
                    path=filepath,
                    uploaded_at=datetime.utcnow()
                ))

    # --- Generate Repayment Schedule
    topup_loan.generate_repayment_schedule()

    # --- Pay Off Base Loan
    if top_up_balance > 0:
        payment = Payment(
            loan_id=base_loan.id,
            amount=top_up_balance,
            method='topup',
            status='successful',
            reference=f"Top-Up from {loan_number}",
            created_at=datetime.utcnow()
        )
        db.session.add(payment)
        db.session.flush()

        base_loan.allocate_payment(payment)
        base_loan.recalculate_balance()

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



from datetime import datetime, timezone

def process_additional_registration(data, base_loan, new_category=None,
                                    loan_form=None, bank_payslip=None, live_photo=None):
    try:
        new_amount = float(data['amount_requested'])
        term_months = int(data['tenure'])
    except (ValueError, KeyError):
        raise ValueError("Invalid loan amount or tenure input.")

    CATEGORY_MAP = {
        1: ('1', 'civil_servant'),
        2: ('2', 'private_sector'),
        3: ('3', 'sme')
    }

    # Use the new_category if provided; else fallback to base_loan.loan_category
    if new_category:
        # Find prefix and category_label from CATEGORY_MAP values by matching new_category
        # CATEGORY_MAP values are tuples like ('1', 'civil_servant'), so find matching label
        category_info = next(((prefix, label) for prefix, label in CATEGORY_MAP.values() if label == new_category), None)
        if not category_info:
            raise ValueError("Unknown new loan category.")
    else:
        category_info = CATEGORY_MAP.get(base_loan.loan_category)
        if not category_info:
            raise ValueError("Unknown base loan category.")

    prefix, category_label = category_info

    config = get_pricing_config(category_label, term_months)
    if not config:
        raise ValueError("Pricing configuration unavailable.")

    crb_fees = config.get('crb', 3000)
    origination_fees = new_amount * config.get('origination', 0)
    insurance_fees = new_amount * config.get('insurance', 0)
    collection_fees = new_amount * config.get('collection', 0)

    capitalized_amount = new_amount + origination_fees + insurance_fees + crb_fees

    rate = config['rate']
    annuity_factor = (rate * (1 + rate) ** term_months) / ((1 + rate) ** term_months - 1)
    monthly_instalment = capitalized_amount * annuity_factor + collection_fees

    now_utc = datetime.now(timezone.utc)

    loan_sequence = str(db.session.query(LoanApplication).count() + 1).zfill(6)
    loan_number = f"{prefix}{str(term_months).zfill(2)}{loan_sequence}"

    additional_loan = LoanApplication(
        customer_id=base_loan.customer_id,
        loan_amount=new_amount,
        term_months=term_months,
        monthly_instalment=round(monthly_instalment, 2),
        total_repayment=round(monthly_instalment * term_months, 2),
        effective_rate=calculate_eir(new_amount, term_months, config),
        category=category_label,
        loan_category=int(prefix),  # keep the numeric loan_category consistent
        loan_number=loan_number,
        file_number=base_loan.file_number,
        application_status='pending',
        loan_state='active',
        crb_fees=crb_fees,
        origination_fees=round(origination_fees, 2),
        insurance_fees=round(insurance_fees, 2),
        collection_fees=round(collection_fees, 2),
        parent_loan_id=None,
        date_created=now_utc,
        disbursement_date=None,
        cash_to_client=new_amount,
        applied_interest_rate=rate,
        applied_collection_fee=config.get('collection', 0),
    )

    db.session.add(additional_loan)
    db.session.flush()

    for file_obj, filetype in [
        (loan_form, 'loan_form'),
        (bank_payslip, 'bank_payslip'),
        (live_photo, 'live_photo')
    ]:
        if file_obj:
            filename, filepath = save_file(file_obj, subfolder=f"additional_loan_{additional_loan.id}")
            if filename:
                doc = Document(
                    customer_id=base_loan.customer_id,
                    loan_id=additional_loan.id,
                    filename=filename,
                    filetype=filetype,
                    path=filepath,
                    uploaded_at=now_utc
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

@app.route("/settle_loan/<int:loan_id>", methods=["POST"])
@login_required
@role_required("finance_officer", "admin")
def settle_loan(loan_id):
    loan = LoanApplication.query.get_or_404(loan_id)
    customer = loan.customer

    try:
        closure_type = request.form.get("closure_type", "settlement").strip()
        settlement_str = request.form.get("settlement_type", "").strip()
        institution = request.form.get("settling_institution", "").strip() or None
        reason = request.form.get("settlement_reason", "").strip() or None

        VALID_CLOSURES = {"settlement", "insurance", "write_off"}
        if closure_type not in VALID_CLOSURES:
            flash("Invalid closure type selected.", "danger")
            return redirect_to_referrer(customer.file_number)

        if closure_type in {"write_off", "settlement"} and not reason:
            flash("Settlement reason is required.", "danger")
            return redirect_to_referrer(customer.file_number)

        if closure_type == "settlement":
            if settlement_str not in {"self", "third_party"}:
                flash("Invalid settlement sub-type selected.", "danger")
                return redirect_to_referrer(customer.file_number)
            loan.settlement_type = (
                SettlementTypeEnum.self_settlement if settlement_str == "self"
                else SettlementTypeEnum.third_party
            )
        else:
            loan.settlement_type = None

        loan.settling_institution = institution
        loan.settlement_reason = reason

        if loan.loan_state != "active":
            flash("Cannot settle a non-active loan.", "danger")
            return redirect_to_referrer(customer.file_number)

        file = request.files.get("settle_file")
        if not file or file.filename == "":
            flash("Settlement proof document is required.", "danger")
            return redirect_to_referrer(customer.file_number)

        filename = secure_filename(
            f"settlement_{loan.loan_number}_{datetime.utcnow():%Y%m%d%H%M%S}{os.path.splitext(file.filename)[1]}"
        )
        folder = os.path.join(app.config["UPLOAD_FOLDER"], "settlements")
        os.makedirs(folder, exist_ok=True)
        file.save(os.path.join(folder, filename))

        loan.recalculate_balance()
        db.session.flush()
        bal = calculate_balances(loan)

        if closure_type == "settlement":
            principal = bal["current_balance"]
            interest = bal["settlement_interest"]
            amount_to_pay = bal["settlement_balance"]
        else:
            principal = bal["current_balance"]
            interest = 0.0
            amount_to_pay = principal

            if closure_type == "write_off":
                loan.written_off_amount = round(amount_to_pay, 2)
            elif closure_type == "insurance":
                loan.insurance_settlement_amount = round(amount_to_pay, 2)

        if amount_to_pay <= 0:
            flash("Settlement balance must be greater than zero.", "danger")
            return redirect_to_referrer(customer.file_number)

        payment = Payment(
            loan_id=loan.id,
            amount=amount_to_pay,
            method="settlement",
            status="completed",
            reference=f"{closure_type.replace('_',' ').title()} for {loan.loan_number}",
            settlement_proof=filename,
        )
        db.session.add(payment)
        db.session.flush()

        alloc = PaymentAllocation(
            payment_id=payment.id,
            principal=principal,
            interest=0.0,
            fees=0.0,
            settlement_interest=interest,
        )
        db.session.add(alloc)

        loan.loan_state = "settled_client" if closure_type == "settlement" else closure_type
        loan.closure_type = closure_type
        loan.closure_date = datetime.utcnow()
        loan.settlement_balance = round(principal + interest, 2)
        loan.current_balance = 0.0
        loan.top_up_balance = 0.0

        for sched in loan.repayment_schedules:
            if sched.status != "paid":
                sched.status = "settled"

        db.session.commit()
        flash(f"Loan {loan.loan_number} settled successfully.", "success")

    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Settlement error for loan {loan_id}: {str(e)}", exc_info=True)
        flash(f"Error settling loan: {str(e)}", "danger")

    return redirect_to_referrer(customer.file_number)


# Helper function for consistent redirects
def redirect_to_referrer(file_number):
    return redirect(request.referrer or url_for("customer_account", 
                                              file_number=file_number,
                                              section="settlement"))

@app.route('/settlement_report')
@login_required
@role_required('finance_officer', 'admin')
def settlement_report():
    settled_loans = (
        db.session.query(
            LoanApplication.loan_number,
            LoanApplication.loan_state,
            LoanApplication.settlement_balance,
            Payment.amount.label('paid_amount'),
            PaymentAllocation.principal.label('paid_principal'),
            PaymentAllocation.settlement_interest.label('paid_settlement_interest'),
            Payment.created_at.label('payment_date')
        )
        .join(Payment, Payment.loan_id == LoanApplication.id)
        .join(PaymentAllocation, PaymentAllocation.payment_id == Payment.id)
        .filter(
            LoanApplication.loan_state == 'settled_client',
            Payment.method == 'settlement',
            Payment.status == 'completed'
        )
        .order_by(Payment.created_at.desc())
        .all()
    )

    print(f"[DEBUG] Settled loans count: {len(settled_loans)}")  # helps you debug

    return render_template(
        'settlement_report.html',
        settled_loans=settled_loans
    )

import csv
from io import StringIO
from flask import Response

@app.route('/export_settlement_report_csv')
@login_required
@role_required('finance_officer', 'admin')
def export_settlement_report_csv():
    settled_loans = (
        db.session.query(
            LoanApplication.loan_number,
            LoanApplication.loan_state,
            LoanApplication.settlement_balance,
            Payment.amount.label('paid_amount'),
            PaymentAllocation.principal.label('paid_principal'),
            PaymentAllocation.settlement_interest.label('paid_settlement_interest'),
            Payment.created_at.label('payment_date')
        )
        .join(Payment, Payment.loan_id == LoanApplication.id)
        .join(PaymentAllocation, PaymentAllocation.payment_id == Payment.id)
        .filter(
            LoanApplication.loan_state == 'settled_client',
            Payment.method == 'settlement',
            Payment.status == 'completed'
        )
        .order_by(Payment.created_at.desc())
        .all()
    )

    si = StringIO()
    cw = csv.writer(si)
    cw.writerow(['Loan Number', 'Loan State', 'Settlement Balance', 'Amount Paid', 'Principal Paid', 'Settlement Interest Paid', 'Payment Date'])
    for loan in settled_loans:
        cw.writerow([
            loan.loan_number,
            loan.loan_state,
            loan.settlement_balance or 0.0,
            loan.paid_amount or 0.0,
            loan.paid_principal or 0.0,
            loan.paid_settlement_interest or 0.0,
            loan.payment_date.strftime('%Y-%m-%d %H:%M') if loan.payment_date else ''
        ])

    output = Response(si.getvalue(), mimetype='text/csv')
    output.headers["Content-Disposition"] = "attachment; filename=settlement_report.csv"
    return output



@app.route('/batch_write_off', methods=['POST'])
@login_required
@role_required('finance_officer', 'admin')
def batch_write_off():
    if 'csv_file' not in request.files:
        flash('No file part', 'danger')
        return redirect(request.referrer)
    
    file = request.files['csv_file']
    if file.filename == '':
        flash('No selected file', 'danger')
        return redirect(request.referrer)
    
    if file and allowed_file(file.filename):
        try:
            stream = io.StringIO(file.stream.read().decode("UTF8"), newline=None)
            csv_reader = csv.DictReader(stream)
            
            processed = 0
            for row in csv_reader:
                loan_number = row.get('loan_number')
                reason = row.get('reason', 'No reason provided')
                
                loan = LoanApplication.query.filter_by(loan_number=loan_number).first()
                if loan:
                    loan.loan_state = 'written_off'
                    loan.closure_type = 'write_off'
                    loan.closure_date = datetime.utcnow()
                    db.session.add(loan)
                    processed += 1
            
            db.session.commit()
            flash(f'Successfully processed {processed} loans', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'Error processing CSV: {str(e)}', 'danger')
    else:
        flash('Invalid file type', 'danger')
    
    return redirect(request.referrer)

from datetime import datetime, timedelta, date
import calendar
import csv
from io import StringIO
from flask import render_template, request, Response
from sqlalchemy import func


def _parse_date(s, default):
    try:
        return datetime.strptime(s, '%Y-%m-%d').date()
    except (TypeError, ValueError):
        return default


def _compute_income_db(start_date, end_date):
    start_dt = datetime.combine(start_date, datetime.min.time())
    end_dt = datetime.combine(end_date + timedelta(days=1), datetime.min.time())

    # One-time income (based on creation date)
    one_time = (
        db.session.query(
            LoanApplication.category,
            func.coalesce(func.sum(LoanApplication.origination_fees), 0).label('origination'),
            func.coalesce(func.sum(LoanApplication.crb_fees), 0).label('crb'),
            func.coalesce(func.sum(LoanApplication.insurance_fees), 0).label('insurance')
        )
        .filter(
            LoanApplication.created_at >= start_dt,
            LoanApplication.created_at < end_dt,
            LoanApplication.application_status == 'approved'
        )
        .group_by(LoanApplication.category)
        .all()
    )

    # Accrued income (scheduled interest & fees)
    accrued = (
        db.session.query(
            LoanApplication.category,
            func.coalesce(func.sum(RepaymentSchedule.expected_interest), 0).label('interest'),
            func.coalesce(func.sum(RepaymentSchedule.expected_fees), 0).label('collection')
        )
        .join(LoanApplication, LoanApplication.id == RepaymentSchedule.loan_id)
        .filter(
            RepaymentSchedule.due_date >= start_date,
            RepaymentSchedule.due_date <= end_date,
            LoanApplication.loan_state.in_(['active', 'topped_up'])
        )
        .group_by(LoanApplication.category)
        .all()
    )

    # Cash-based payments (optional but retained)
    recurring = (
        db.session.query(
            LoanApplication.category,
            func.coalesce(func.sum(PaymentAllocation.fees), 0).label('collection'),
            func.coalesce(func.sum(PaymentAllocation.interest), 0).label('interest')
        )
        .join(Payment, Payment.id == PaymentAllocation.payment_id)
        .join(LoanApplication, LoanApplication.id == Payment.loan_id)
        .filter(
            Payment.created_at >= start_dt,
            Payment.created_at < end_dt,
            Payment.status == 'successful'
        )
        .group_by(LoanApplication.category)
        .all()
    )

    return one_time, accrued, recurring




@app.route('/income_report', methods=['GET', 'POST'])
@login_required
@role_required('finance_officer', 'admin')
def income_report():
    today = date.today()
    default_start = date(today.year, today.month, 1)
    default_end = date(today.year, today.month, calendar.monthrange(today.year, today.month)[1])

    if request.method == 'POST':
        start_date = _parse_date(request.form.get('start_date'), default_start)
        end_date = _parse_date(request.form.get('end_date'), default_end)
    else:
        start_date, end_date = default_start, default_end

    one_time, accrued, recurring = _compute_income_db(start_date, end_date)

    categories = ['civil_servant', 'private_sector', 'sme']
    report = {cat: dict(origination=0, crb=0, insurance=0, collection=0, interest=0) for cat in categories}

    for row in one_time:
        if row.category in report:
            report[row.category].update(origination=row.origination, crb=row.crb, insurance=row.insurance)

    for row in accrued:
        if row.category in report:
            report[row.category]['interest'] = row.interest
            report[row.category]['collection'] = row.collection

    totals = {k: sum(report[cat][k] for cat in categories) for k in report[categories[0]]}
    grand_total = sum(totals.values())

    return render_template('income_report.html',
                           report=report,
                           totals=totals,
                           grand_total=grand_total,
                           start_date=start_date.isoformat(),
                           end_date=end_date.isoformat(),
                           categories=categories)


@app.route('/export_income_report_csv')
@login_required
@role_required('finance_officer', 'admin')
def export_income_report_csv():
    start_date = _parse_date(request.args.get('start_date'), date.today().replace(day=1))
    end_date = _parse_date(request.args.get('end_date'), date.today())

    one_time, accrued, recurring = _compute_income_db(start_date, end_date)

    categories = ['civil_servant', 'private_sector', 'sme']
    report = {cat: dict(origination=0, crb=0, insurance=0, collection=0, interest=0) for cat in categories}

    for row in one_time:
        if row.category in report:
            report[row.category].update(origination=row.origination, crb=row.crb, insurance=row.insurance)

    for row in accrued:
        if row.category in report:
            report[row.category]['interest'] = row.interest
            report[row.category]['collection'] = row.collection

    totals = {k: sum(report[cat][k] for cat in categories) for k in report[categories[0]]}
    grand_total = sum(totals.values())

    si = StringIO()
    cw = csv.writer(si)
    cw.writerow(['Category', 'Origination Fees', 'CRB Fees', 'Insurance Fees',
                 'Collection Fees', 'Interest Income', 'Total Income'])

    for cat in categories:
        vals = report[cat]
        cat_total = sum(vals.values())
        cw.writerow([cat.replace('_', ' ').title(),
                     vals['origination'], vals['crb'], vals['insurance'],
                     vals['collection'], vals['interest'], cat_total])

    cw.writerow(['TOTAL',
                 totals['origination'], totals['crb'], totals['insurance'],
                 totals['collection'], totals['interest'], grand_total])

    output = Response(si.getvalue(), mimetype='text/csv')
    output.headers["Content-Disposition"] = (
        f"attachment; filename=income_report_{start_date}_{end_date}.csv"
    )
    return output



from flask import request, flash, redirect, url_for, render_template, Response, current_app
from flask_login import login_required, current_user
import csv
import io
import os
import traceback
import re
from datetime import datetime
from werkzeug.utils import secure_filename
from sqlalchemy.exc import IntegrityError

# Configuration
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB
MAX_ROWS = 1000
ALLOWED_EXTENSIONS = {'csv'}

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def safe_int(value, field_name, default=None):
    """Safely convert to integer with error handling"""
    if not value or value.strip() == '':
        if default is not None:
            return default
        return None
    try:
        return int(value)
    except ValueError:
        raise ValueError(f"Invalid integer value for {field_name}: '{value}'")

def safe_float(value, field_name, default=None):
    """Safely convert to float with error handling"""
    if not value or value.strip() == '':
        if default is not None:
            return default
        return None
    
    # Clean currency values
    clean_value = re.sub(r'[^\d.]', '', value)
    
    try:
        return float(clean_value)
    except ValueError:
        raise ValueError(f"Invalid float value for {field_name}: '{value}'")

def safe_date(value, field_name):
    """Safely convert to date with error handling"""
    if not value or value.strip() == '':
        raise ValueError(f"{field_name} is required and cannot be empty")
    try:
        return datetime.strptime(value.strip(), '%Y-%m-%d')
    except ValueError:
        # Try alternative formats
        try:
            return datetime.strptime(value.strip(), '%m/%d/%Y')
        except ValueError:
            try:
                return datetime.strptime(value.strip(), '%d-%m-%Y')
            except ValueError:
                raise ValueError(f"Invalid date format for {field_name}. Use YYYY-MM-DD")

def get_field(row, field_name, aliases=None, default=''):
    """
    Robust field retrieval with:
    - Case insensitivity
    - Alias support
    - Whitespace trimming
    - Default values
    """
    if aliases is None:
        aliases = []
    
    # Normalize all keys to lowercase
    normalized_row = {k.strip().lower(): v for k, v in row.items()}
    search_terms = [field_name.lower()] + [alias.lower() for alias in aliases]
    
    for term in search_terms:
        if term in normalized_row:
            value = normalized_row[term]
            return value.strip() if isinstance(value, str) else str(value)
    
    return default

@app.route('/admin/batch_import_loans', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def batch_import_loans():
    if request.method == 'POST':
        # Check if file was uploaded
        if 'file' not in request.files:
            flash('No file part', 'danger')
            return redirect(request.url)
        
        file = request.files['file']
        
        # Check if file is selected
        if file.filename == '':
            flash('No selected file', 'danger')
            return redirect(request.url)
        
        # Check file size
        if request.content_length > MAX_FILE_SIZE:
            flash(f'File size exceeds {MAX_FILE_SIZE//(1024*1024)}MB limit', 'danger')
            return redirect(request.url)
        
        # Check file extension
        if not allowed_file(file.filename):
            flash('Invalid file type. Only CSV files are allowed', 'danger')
            return redirect(request.url)
        
        # Secure filename and read stream
        filename = secure_filename(file.filename)
        try:
            stream = io.StringIO(file.stream.read().decode('UTF-8', errors='replace'), newline=None)
        except UnicodeDecodeError:
            flash('Invalid file encoding. Please use UTF-8 encoded CSV files.', 'danger')
            return redirect(request.url)
        
        try:
            # Parse CSV
            reader = csv.DictReader(stream)
            if not reader.fieldnames:
                flash('CSV file is empty or missing headers', 'danger')
                return redirect(request.url)
            
            # Log headers for debugging
            current_app.logger.info(f"CSV headers: {reader.fieldnames}")
            
            # Validate required columns
            required_columns = ['loan_number']
            missing_columns = [col for col in required_columns if col not in reader.fieldnames]
            
            if missing_columns:
                flash(f'Missing required columns: {", ".join(missing_columns)}', 'danger')
                return redirect(request.url)
            
            updated_count = 0
            zeroized_count = 0
            row_errors = []
            empty_row_count = 0
            
            # Define all editable fields and their handlers
            editable_fields = {
                # Financial fields (trigger schedule regeneration)
                'loan_amount': {
                    'handler': lambda v: safe_float(v, 'loan_amount'),
                    'field': 'loan_amount',
                    'trigger_regeneration': True
                },
                'term_months': {
                    'handler': lambda v: safe_int(v, 'term_months'),
                    'field': 'term_months',
                    'trigger_regeneration': True
                },
                'interest_rate': {
                    'handler': lambda v: safe_float(v, 'interest_rate'),
                    'field': 'interest_rate',
                    'trigger_regeneration': True
                },
                'disbursement_date': {
                    'handler': lambda v: safe_date(v, 'disbursement_date'),
                    'field': 'disbursement_date',
                    'trigger_regeneration': True
                },
                
                # Status fields
                'application_status': {
                    'handler': str,
                    'field': 'application_status',
                    'trigger_regeneration': False
                },
                'loan_state': {
                    'handler': str,
                    'field': 'loan_state',
                    'trigger_regeneration': False
                },
                'performance_status': {
                    'handler': str,
                    'field': 'performance_status',
                    'trigger_regeneration': False
                },
                
                # Client information fields
                'client_name': {
                    'handler': str,
                    'field': 'client_name',
                    'trigger_regeneration': False
                },
                'national_id': {
                    'handler': str,
                    'field': 'national_id',
                    'trigger_regeneration': False
                },
                'phone_number': {
                    'handler': str,
                    'field': 'phone_number',
                    'trigger_regeneration': False
                },
                'email': {
                    'handler': str,
                    'field': 'email',
                    'trigger_regeneration': False
                },
                'business_name': {
                    'handler': str,
                    'field': 'business_name',
                    'trigger_regeneration': False
                },
                'business_sector': {
                    'handler': str,
                    'field': 'business_sector',
                    'trigger_regeneration': False
                },
                'business_address': {
                    'handler': str,
                    'field': 'business_address',
                    'trigger_regeneration': False
                },
                
                # Special backdating field
                'created_at': {
                    'handler': lambda v: safe_date(v, 'created_at'),
                    'field': None,  # Handled separately
                    'trigger_regeneration': True
                }
            }
            
            # Process rows
            for idx, row in enumerate(reader, start=1):
                if idx > MAX_ROWS:
                    flash(f'Stopped processing at row {MAX_ROWS} (max limit reached)', 'warning')
                    break
                
                # Skip completely empty rows
                if all(v.strip() == '' for v in row.values() if isinstance(v, str)):
                    empty_row_count += 1
                    continue
                
                try:
                    # Get loan number (required)
                    loan_number = get_field(row, 'loan_number', aliases=['loan_id', 'id'])
                    if not loan_number:
                        raise ValueError("loan_number is required")
                    
                    # Find existing loan
                    loan = LoanApplication.query.filter_by(loan_number=loan_number).first()
                    if not loan:
                        raise ValueError(f"Loan with number {loan_number} not found")
                    
                    # Track if we need to regenerate schedule
                    regenerate_schedule = False
                    set_loan_amount_to_zero = False
                    
                    # Process all editable fields
                    for field_name, config in editable_fields.items():
                        value_str = get_field(row, field_name)
                        if value_str:
                            try:
                                # Special handling for created_at (backdating)
                                if field_name == 'created_at':
                                    created_at = config['handler'](value_str)
                                    loan.created_at = created_at
                                    loan.disbursement_date = created_at
                                    loan.date_created = created_at
                                    regenerate_schedule = True
                                    continue
                                
                                # Process other fields
                                value = config['handler'](value_str)
                                setattr(loan, config['field'], value)
                                
                                # Track if loan amount is being set to zero
                                if field_name == 'loan_amount' and value == 0:
                                    set_loan_amount_to_zero = True
                                
                                # Mark for regeneration if needed
                                if config['trigger_regeneration']:
                                    regenerate_schedule = True
                                    
                            except Exception as e:
                                raise ValueError(f"Error processing '{field_name}': {str(e)}")
                    
                    # Handle zeroization if loan amount is set to 0
                    if set_loan_amount_to_zero:
                        zeroized_count += 1
                        loan.monthly_instalment = 0
                        loan.total_repayment = 0
                        loan.cash_to_client = 0
                        loan.crb_fees = 0
                        loan.performance_status = 'zeroized'
                    
                    # Regenerate repayment schedule if needed
                    if regenerate_schedule:
                        # Explicitly delete existing repayment schedule
                        RepaymentSchedule.query.filter_by(loan_id=loan.id).delete()
                        
                        # Only regenerate if not zeroized
                        if loan.loan_amount > 0:
                            # Use the current disbursement date for schedule generation
                            start_date = loan.disbursement_date
                            loan.generate_repayment_schedule(disbursement_date=start_date)
                    
                    # Update loan in database
                    db.session.add(loan)
                    updated_count += 1
                    
                except Exception as e:
                    # Log detailed error for debugging
                    current_app.logger.error(f"Error in row {idx}: {str(e)}")
                    current_app.logger.error(f"Row data: {row}")
                    current_app.logger.error(traceback.format_exc())
                    row_errors.append(f"Row {idx}: {str(e)}")
            
            # Commit all changes
            db.session.commit()
            
            # Show results
            if updated_count:
                flash(f'Successfully updated {updated_count} loans', 'success')
            if zeroized_count:
                flash(f'Zeroized {zeroized_count} loans (set amount to 0)', 'info')
            if empty_row_count:
                flash(f'Skipped {empty_row_count} empty rows', 'info')
            
            if row_errors:
                flash_errors = "\n".join(row_errors[:10])  # Show first 10 errors
                if len(row_errors) > 10:
                    flash_errors += f"\n...and {len(row_errors)-10} more errors"
                flash(f'Errors encountered:\n{flash_errors}', 'warning')
            
            return redirect(url_for('batch_import_loans'))
        
        except Exception as e:
            db.session.rollback()
            current_app.logger.error(f"Batch update failed: {str(e)}")
            current_app.logger.error(traceback.format_exc())
            flash(f'Failed to process file: {str(e)}', 'danger')
            return redirect(request.url)
    
    # For GET requests, show the import form
    return render_template('admin_dashboard.html', section='batch_import')

# Sample CSV Download Endpoint
@app.route('/admin/download_sample_csv')
@login_required
@role_required('admin')
def download_sample_csv():
    sample_data = """loan_number,created_at,loan_amount,term_months,interest_rate,application_status,loan_state,performance_status,client_name,national_id,phone_number,email,business_name,business_sector,business_address
LOAN-2023-001,2023-05-15,0,12,15,Approved,Closed,Zeroized,John Doe,12345678,0712345678,john@example.com,John Enterprises,Retail,Nairobi
LOAN-2023-002,2023-06-01,500000.00,24,12,Approved,Active,Performing,Jane Smith,87654321,0798765432,jane@example.com,Jane Ltd,Manufacturing,Mombasa
LOAN-2023-003,2023-07-10,,,,Approved,Active,Performing,Robert Brown,,,,,,"""

    return Response(
        sample_data,
        mimetype="text/csv",
        headers={"Content-disposition": "attachment; filename=loan_updates_sample.csv"}
    )

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

from app import app, db

def initialize_roles_permissions():
    with app.app_context():
        create_roles_and_permissions()

@app.route('/db-check')
def db_check():
    try:
        db.engine.connect()
        return "Database connection successful!", 200
    except Exception as e:
        return f"Database connection failed: {str(e)}", 500

def deploy():
    with app.app_context():
        # Apply any pending migrations
        upgrade()

if __name__ == '__main__':
    try:
        deploy()
    except Exception as e:
        print(f"Migration failed: {e}", file=sys.stderr)
        sys.exit(1)

    initialize_roles_permissions()
    app.run(debug=True)