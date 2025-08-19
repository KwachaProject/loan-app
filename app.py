from flask import Flask, render_template, request, redirect, url_for, flash, send_file, jsonify, abort 
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from sqlalchemy.exc import IntegrityError
from datetime import datetime, timedelta, time
from io import BytesIO
from fpdf import FPDF
from calendar import monthrange
import json
from datetime import timedelta
from contextlib import contextmanager
from sqlalchemy.exc import ProgrammingError
import inspect
from sqlalchemy import text
from sqlalchemy import desc
from sqlalchemy import exc as sa_exc, inspect
from sqlalchemy.exc import ProgrammingError
from jinja2 import TemplateNotFound
from flask_apscheduler import APScheduler
from sqlalchemy import or_
from sqlalchemy import func
from flask_apscheduler import APScheduler
from flask_mail import Message
from wtforms.validators import DataRequired, Length, Optional
import calendar
from urllib.parse import quote
from sqlalchemy import Column, Integer, String, Float, ForeignKey
from sqlalchemy.orm import relationship, backref
from sqlalchemy import event
import shutil
import mimetypes
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
from sqlalchemy.exc import IntegrityError
from flask import make_response
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
from apscheduler.schedulers.background import BackgroundScheduler
from flask_wtf import FlaskForm
from wtforms.validators import DataRequired, Email
from wtforms import StringField, FloatField, IntegerField, SelectField, DateField, SubmitField
import os
import re
from werkzeug.utils import secure_filename
from sqlalchemy.orm import joinedload
from flask import Flask
from flask_mail import Mail, Message
from apscheduler.schedulers.background import BackgroundScheduler
from datetime import date, datetime, timedelta
from flask import Flask, render_template
from flask_mail import Mail, Message
from apscheduler.schedulers.background import BackgroundScheduler
from datetime import date, datetime, timedelta
import calendar
import os
from sqlalchemy import create_engine, func, extract
from sqlalchemy.orm import sessionmaker
import pandas as pd
import numpy as np
import calendar
from sqlalchemy import func

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

app.config.update({
    'UPLOAD_FOLDER': os.path.join(app.instance_path, 'documents'),
    'MAX_CONTENT_LENGTH': 16 * 1024 * 1024,  # 16MB max upload
})
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

password = os.getenv('MAIL_PASSWORD', '')
if not password:
    raise ValueError("MAIL_PASSWORD environment variable is not set")

safe_password = re.escape(password)

safe_password = quote(password)

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

def format_currency(value):
    try:
        value = float(value)
        return "MWK{:,.2f}".format(value)
    except (ValueError, TypeError):
        return value


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

# In your app.py or __init__.py


logging.basicConfig(
    filename='app.log',
    filemode='a',
    encoding='utf-8',  # <-- important
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
    )

app = Flask(__name__)

# Determine the environment: "production" or "development"
db = SQLAlchemy()
migrate = Migrate()
mail = Mail()

# Initialize APSchedule

# Create Flask app



@app.template_filter('unique')
def unique_filter(items, attribute):
    seen = set()
    result = []
    for item in items:
        value = getattr(item, attribute)
        if value not in seen:
            seen.add(value)
            result.append(item)
    return result
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
app.config.update(
    MAIL_SERVER='mail.kwachafinancialservices.com',
    MAIL_PORT=465,
    MAIL_USE_SSL=True,
    MAIL_USERNAME=os.getenv('MAIL_USERNAME'),
    MAIL_PASSWORD=os.getenv('MAIL_PASSWORD'),
    MAIL_DEFAULT_SENDER=os.getenv('MAIL_USERNAME'),
    SQLALCHEMY_TRACK_MODIFICATIONS=False
)

MAIL_USERNAME = os.getenv('MAIL_USERNAME')
MAIL_PASSWORD = os.getenv('MAIL_PASSWORD')

if not MAIL_USERNAME or not MAIL_PASSWORD:
    raise ValueError("MAIL_USERNAME or MAIL_PASSWORD is not set in environment variables")


app.config['SCHEDULER_API_ENABLED'] = True
app.config['SCHEDULER_TIMEZONE'] = 'Africa/Blantyre' 

# File upload settings
app.config['UPLOAD_FOLDER'] = 'uploads/documents'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'pdf', 'doc', 'docx'}

mail = Mail(app)


from apscheduler.schedulers.background import BackgroundScheduler
scheduler = BackgroundScheduler(daemon=True)

# Security
app.config['SECRET_KEY'] = 'your-secret-key-123'  # ✅ Change this in production!

# Initialize extensions with app
db.init_app(app)
migrate.init_app(app, db)
mail.init_app(app)

login_manager = LoginManager(app)

scheduler = APScheduler()
  # Make sure 'app' is your Flask application instance

# Import models after initializing the db instance
from app import db

UPLOAD_FOLDER = 'uploads/documents'
MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16 MB max upload size
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'pdf', 'doc', 'docx'}


import socket
app.jinja_env.filters['format_currency'] = format_currency

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

db.metadata.clear()

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('email_scheduler.log')
    ]
)
logger = logging.getLogger(__name__)


@contextmanager
def app_context():
    """Ensure application context"""
    ctx = app.app_context()
    try:
        ctx.push()
        yield
    finally:
        ctx.pop()


@app.route('/serve_document/<int:doc_id>')
def serve_document(doc_id):
    doc = Document.query.get_or_404(doc_id)
    abs_path = doc.get_absolute_path()
    
    if not abs_path or not os.path.exists(abs_path):
        app.logger.error(f"Document file missing: {doc.path}")
        abort(404)
    
    return send_file(abs_path)

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
    __table_args__ = {'extend_existing': True}
    
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

from app import db  # or wherever your SQLAlchemy instance is

class Notification(db.Model):
    __tablename__ = 'notifications'

    id = db.Column(db.Integer, primary_key=True)
    recipient_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)  # Null = global
    recipient = db.relationship('User', backref='notifications')
    
    # Email specific fields
    email_recipients = db.Column(db.Text, nullable=True)  # Comma-separated email addresses
    email_subject = db.Column(db.String(200))
    email_content = db.Column(db.Text)
    
    # Status tracking
    email_sent = db.Column(db.Boolean, default=False)
    sent_at = db.Column(db.DateTime)
    
    message = db.Column(db.Text, nullable=False)
    type = db.Column(db.String(50), default='info')
    is_read = db.Column(db.Boolean, default=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f'<Notification {self.type} to {self.email_recipients or self.recipient_id}>'

from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, SubmitField
from wtforms.validators import DataRequired, Email

class RecipientForm(FlaskForm):
    emails = StringField('Recipients', validators=[DataRequired()], description='Comma-separated email addresses')
    subject = StringField('Subject', validators=[DataRequired()])
    message = TextAreaField('Custom Message')
    submit = SubmitField('Send Report')

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

class Agent(db.Model):
    __tablename__ = 'agents'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    contact = db.Column(db.String(20))
    email = db.Column(db.String(100))
    district = db.Column(db.String(100))
    region = db.Column(db.String(100))
    monthly_budget = db.Column(db.Float, default=0.0)
    role = db.Column(db.String(50))
    active = db.Column(db.Boolean, default=True)

    # Self-referencing relationship
    team_leader_id = db.Column(db.Integer, db.ForeignKey('agents.id'), nullable=True)
    team_leader = db.relationship('Agent', remote_side=[id], backref='team_members')

    # If you have customers
    customers = db.relationship('Customer', back_populates='agent', lazy=True)

    @property
    def team_sales(self):
        """Get MTD sales for the team"""
        from datetime import datetime
        today = datetime.utcnow().date()
        month_start = today.replace(day=1)
        
        return db.session.query(
            func.sum(LoanApplication.loan_amount)
        ).join(Agent).filter(
            LoanApplication.disbursement_date >= month_start,
            LoanApplication.disbursement_date <= today,
            LoanApplication.disbursed == True,
            or_(
                LoanApplication.agent_id == self.id,
                Agent.team_leader_id == self.id
            )
        ).scalar() or 0.0
    
    @property
    def achievement_percentage(self):
        """Calculate achievement percentage"""
        if self.monthly_budget:
            return min(round((self.team_sales / self.monthly_budget) * 100, 1), 150)
        return 0.0
    
    @property
    def performance_status(self):
        """Get performance status label"""
        achievement = self.achievement_percentage
        if achievement >= 100:
            return "exceeded"
        elif achievement >= 75:
            return "on-track"
        else:
            return "needs-improvement"
    


class Customer(db.Model):
    __tablename__ = 'customers'
    __table_args__ = (
        db.UniqueConstraint('national_id', name='uq_customers_national_id'),
        db.UniqueConstraint('file_number', name='uq_customers_file_number'),
        db.UniqueConstraint('employment_number', name='uq_customers_employment_number'),
        db.Index('idx_customers_national_id', 'national_id'),
        db.Index('idx_customers_file_number', 'file_number'),
        db.Index('idx_customers_employment_number', 'employment_number'),
        db.Index('idx_customers_agent_id', 'agent_id'),
    )
    
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
    agent_id = db.Column(db.Integer, db.ForeignKey('agents.id'), nullable=True)
    employment_number = db.Column(db.String(20), unique=True, nullable=True) 

    loans = db.relationship('LoanApplication', back_populates='customer')
    
    agent = db.relationship('Agent', back_populates='customers')

    customer_documents = db.relationship("Document", back_populates="customer", lazy=True)

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

class CustomerQueryForm(FlaskForm):
    national_id = StringField('National ID', validators=[Optional()])
    employment_number = StringField('Employment Number', validators=[Optional()])
    query_submit = SubmitField('Search Customer')

class CutoffDateConfig(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    category = db.Column(db.String(50), unique=True, nullable=False)  # 'civil_servant', 'private_sector', etc.
    cutoff_dt = db.Column(db.DateTime, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class LoanApplication(db.Model):
    __tablename__ = 'loan_applications'
    __table_args__ = (
        db.UniqueConstraint('loan_number', name='uq_loan_applications_loan_number'),
        db.Index('ix_loan_applications_created_at', 'created_at'),
        db.Index('ix_loan_applications_region_category', 'region', 'category'),
        db.Index('idx_loan_applications_loan_number', 'loan_number'),
        db.Index('idx_loan_applications_customer_id', 'customer_id'),
        db.Index('idx_loan_applications_agent_id', 'agent_id'),
    )


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
    region = db.Column(db.String(50))
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
    agent_id = db.Column(db.Integer, db.ForeignKey('agents.id'), nullable=True)

    parent_loan_id = db.Column(
        db.Integer, 
        db.ForeignKey('loan_applications.id'),
        nullable=True
    )
    
    vote = db.relationship('Vote', backref='loan_applications')

    documents = db.relationship("Document", back_populates="loan", lazy=True)

    topups = db.relationship(
        'LoanApplication',
        foreign_keys=[parent_loan_id],  # 👈 Specify which foreign key to use
        backref=db.backref('parent_loan', remote_side=[id]),
        cascade='all, delete-orphan'
    )

    agent = db.relationship("Agent", backref="loan_applications", foreign_keys=[agent_id])
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
    def has_unreconciled_deductions(self):
        for sched in self.repayment_schedules:
            payroll = PayrollDeduction.query.filter_by(
                loan_id=self.id,
                deduction_date=sched.due_date
            ).first()
            if not payroll or payroll.amount < sched.expected_amount:
                return True
        return False



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
        from dateutil.relativedelta import relativedelta
        
        current_app.logger.info(f"Generating repayment schedule for loan {self.loan_number} with disbursement_date={disbursement_date}")

        # Delete old schedules
        for sched in self.repayment_schedules:
            db.session.delete(sched)
        db.session.flush()

        config = get_pricing_config(self.category, self.term_months, self)
        if not config:
            current_app.logger.warning("No pricing config found, aborting schedule generation.")
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
            current_app.logger.warning("Term months is zero or negative, aborting schedule generation.")
            return

        first_due = self.get_first_due_date(disbursement_date)
        current_app.logger.info(f"First due date: {first_due}")

        if monthly_rate > 0:
            fac = (monthly_rate * (1 + monthly_rate) ** term) / ((1 + monthly_rate) ** term - 1)
            annuity_princ_int = capitalised * fac
        else:
            annuity_princ_int = capitalised / term

        remaining = capitalised

        for i in range(term):
            due_date = first_due + relativedelta(months=i)
            interest = remaining * monthly_rate
            principal = annuity_princ_int - interest

            if i == term - 1:
                principal = remaining
                interest = annuity_princ_int - principal
                annuity_princ_int = principal + interest

            remaining -= principal
            remaining = max(0, round(remaining, 2))

            current_app.logger.info(f"Instalment {i+1}: Due {due_date}, Principal {principal:.2f}, Interest {interest:.2f}, Fees {coll_fee_flat:.2f}")

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

        db.session.flush()

    
    # Do NOT commit here - handled by caller

    from datetime import datetime
    from dateutil.relativedelta import relativedelta   # already using
    import calendar

    # … other methods in LoanApplication …

    def allocate_payment(self, payment):
        # Early exit if loan is closed
        if self.loan_state in {"settled_client", "write_off", "insurance"}:
            app.logger.warning(f"[{self.loan_number}] Payment not allocated. Loan state is closed: {self.loan_state}")
            return

        remaining = payment.amount
        method = (payment.method or "normal").lower()

        # Normalize method for top-up and settlement
        if "top_up" in method:
            method = "top_up"
        elif "settlement" in method:
            method = "settlement"

        if method == "top_up":
            # Allocate to top-up balance: top_up_balance = current_balance + top_up_interest
            top_up_balance = (self.top_up_balance or 0.0)  # already current_balance + top_up_interest

            principal_alloc = min(self.current_balance, remaining)
            self.current_balance -= principal_alloc
            remaining -= principal_alloc

            # Remaining payment goes to top-up interest part
            top_up_interest_part = max(top_up_balance - self.current_balance, 0.0)
            interest_alloc = min(top_up_interest_part, remaining)
            self.top_up_interest = max((self.top_up_interest or 0.0) - interest_alloc, 0.0)
            remaining -= interest_alloc

            # Update top_up_balance (it should be current_balance + top_up_interest)
            self.top_up_balance = self.current_balance + (self.top_up_interest or 0.0)

            # Save allocation record
            db.session.add(PaymentAllocation(
                payment_id=payment.id,
                principal=principal_alloc,
                interest=0.0,
                top_up_interest=interest_alloc,
                settlement_interest=0.0,
                fees=0.0
            ))

            app.logger.info(
                f"[{self.loan_number}] Top-up payment → principal: {principal_alloc}, top-up interest: {interest_alloc}"
            )

            db.session.commit()

            # Close loan if fully paid off
            if self.current_balance <= 0 and (self.top_up_interest or 0.0) <= 0:
                self.status = "closed"
                self.loan_state = "settled_client"
                app.logger.info(f"[{self.loan_number}] Loan closed after top-up payment.")

                for schedule in self.repayment_schedules:
                    if schedule.status not in {"paid", "cancelled"}:
                        schedule.status = "cancelled"

                db.session.commit()

            # Record overpayment credit if any
            if remaining > 0:
                self.record_loan_credit(payment, remaining)

            return  # Skip normal allocation for top-up payments

        elif method == "settlement":
            # Allocate to settlement interest first, then principal (current balance)
            interest_alloc = min(self.settlement_interest or 0.0, remaining)
            self.settlement_interest = max((self.settlement_interest or 0.0) - interest_alloc, 0.0)
            remaining -= interest_alloc

            principal_alloc = min(self.current_balance, remaining)
            self.current_balance -= principal_alloc
            remaining -= principal_alloc

            db.session.add(PaymentAllocation(
                payment_id=payment.id,
                principal=principal_alloc,
                interest=0.0,
                settlement_interest=interest_alloc,
                fees=0.0
            ))

            app.logger.info(
                f"[{self.loan_number}] Settlement payment → settlement_interest: {interest_alloc}, principal: {principal_alloc}"
            )

            db.session.commit()

            # Close loan if fully paid
            if self.current_balance <= 0 and (self.settlement_interest or 0.0) <= 0:
                self.status = "closed"
                self.loan_state = "settled_client"
                app.logger.info(f"[{self.loan_number}] Loan closed after settlement payment.")
                db.session.commit()

            if remaining > 0:
                self.record_loan_credit(payment, remaining)

            return  # Skip normal allocation for settlement payments

        elif method in {"write_off", "insurance"}:
            # Only allocate towards current balance principal
            principal_alloc = min(self.current_balance, remaining)
            self.current_balance -= principal_alloc
            remaining -= principal_alloc

            db.session.add(PaymentAllocation(
                payment_id=payment.id,
                principal=principal_alloc,
                interest=0.0,
                top_up_interest=0.0,
                settlement_interest=0.0,
                fees=0.0
            ))

            app.logger.info(
                f"[{self.loan_number}] {method} payment → principal: {principal_alloc}"
            )

            db.session.commit()

            # Close loan if fully paid
            if self.current_balance <= 0:
                self.status = "closed"
                self.loan_state = "settled_client"
                app.logger.info(f"[{self.loan_number}] Loan closed after {method} payment.")
                db.session.commit()

            if remaining > 0:
                self.record_loan_credit(payment, remaining)

            return

        else:
            # --- Normal payment allocation: fees → interest → principal ---
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

                if schedule.paid_amount + 0.01 >= schedule.expected_amount:
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
                db.session.commit()

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


    def update_arrears_status(self):
        """Automatically update arrear status based on payments"""
        for arrear in self.arrears:
            if arrear.status == 'unresolved' and arrear.total_arrears <= 0:
                arrear.status = 'resolved'
                arrear.resolution_date = datetime.utcnow()

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


class AuditLog(db.Model):
    __tablename__ = 'audit_logs'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    action = db.Column(db.String(100), nullable=False)
    details = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

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
    schedule_id = db.Column(db.Integer, db.ForeignKey('repayment_schedules.id'), nullable=True)

    principal = db.Column(db.Float, default=0.0)
    interest = db.Column(db.Float, default=0.0)
    fees = db.Column(db.Float, default=0.0)

    # ✅ These must be defined
    top_up_interest = db.Column(db.Float, default=0.0)  # <-- THIS LINE IS REQUIRED
    settlement_interest = db.Column(db.Float, default=0.0)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Relationships
    payment = db.relationship('Payment', back_populates='allocations')
    schedule = db.relationship(
        'RepaymentSchedule',
        primaryjoin='PaymentAllocation.schedule_id == RepaymentSchedule.id',
        foreign_keys=[schedule_id],
        backref='allocations'
    )

    # Remove unique constraint on payment_id to allow multiple allocations per payment
    # __table_args__ = (
    #     db.UniqueConstraint('payment_id', name='uq_payment_allocation_payment_id'),
    # )

    
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
    customer = db.relationship("Customer", back_populates="customer_documents")
    loan = db.relationship("LoanApplication", back_populates="documents")

    def get_absolute_path(self):
        """Get absolute file path with safety checks"""
        if not self.path:
            return None
            
        try:
            # Handle absolute paths directly
            if os.path.isabs(self.path):
                return self.path
                
            # First try: app root relative path
            root_relative = os.path.join(app.root_path, self.path)
            if os.path.exists(root_relative):
                return root_relative
                
            # Second try: instance documents folder
            instance_path = os.path.join(app.instance_path, 'documents', os.path.basename(self.path))
            if os.path.exists(instance_path):
                return instance_path
                
            # Third try: original path as is
            if os.path.exists(self.path):
                return self.path
                
            return None
        except Exception:
            # Log error in production
            app.logger.error(f"Error resolving path for document {self.id}")
            return None
    
    @property
    def absolute_path(self):
        return self.get_absolute_path()
    
    @property
    def file_exists(self):
        """Check if file exists on filesystem"""
        path = self.absolute_path
        return path and os.path.exists(path)
    
class PARSnapshot(db.Model):
    __tablename__ = 'par_snapshots'

    id = db.Column(db.Integer, primary_key=True)
    snapshot_date = db.Column(db.Date, nullable=False, unique=True)
    par_30 = db.Column(db.Float, nullable=False)
    par_60 = db.Column(db.Float, nullable=False)
    par_90 = db.Column(db.Float, nullable=False)
    created_at = db.Column(db.DateTime, server_default=db.func.now())


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
    resolution_date = db.Column(db.DateTime, nullable=True)
    resolution_type = db.Column(db.String(20), nullable=True)  # 'payment', 'waiver', 'restructure'
    resolved_by = db.Column(db.Integer, db.ForeignKey('users.id'))
    resolution_notes = db.Column(db.Text, nullable=True)
    tenure = db.Column(db.Integer)
    probability_of_default = db.Column(db.Float, default=0.0)
    loss_given_default = db.Column(db.Float, default=0.0)
    provision_amount = db.Column(db.Float, default=0.0)
    arrear_reason = db.Column(db.String(100), nullable=True)
    action_plan = db.Column(db.Text, nullable=True)


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

    @property
    def days_past_due(self):
        if self.due_date:
            delta = datetime.utcnow().date() - self.due_date
            return delta.days if delta.days > 0 else 0
        return 0

    @property
    def aging(self):
        days = self.days_past_due
        if days <= 30:
            return '1-30 days'
        elif days <= 60:
            return '31-60 days'
        elif days <= 90:
            return '61-90 days'
        else:
            return '90+ days'
class ProvisionSetting(db.Model):
    __tablename__ = 'provision_settings'

    id = db.Column(db.Integer, primary_key=True)
    category = db.Column(db.String(50), nullable=False)
    tenure = db.Column(db.Integer, nullable=False)  # in months
    probability_of_default = db.Column(db.Float, nullable=False)
    loss_given_default = db.Column(db.Float, nullable=False)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, onupdate=datetime.utcnow)
    
    __table_args__ = (db.UniqueConstraint('category', 'tenure', name='uq_category_tenure'),)

from wtforms.validators import DataRequired, NumberRange
from datetime import datetime, timedelta, date
from decimal import Decimal, ROUND_HALF_UP

# Database Models (unchanged from your specification)
class RelationshipManager(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    phone = db.Column(db.String(20))
    email = db.Column(db.String(120))
    clients = db.relationship('Client', backref='relationship_manager', lazy=True)

class Client(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(120), nullable=False)
    national_id = db.Column(db.String(20), unique=True, nullable=False)
    phone = db.Column(db.String(20))
    email = db.Column(db.String(120))
    relationship_manager_id = db.Column(db.Integer, db.ForeignKey('relationship_manager.id'))
    placements = db.relationship('Placement', backref='client', lazy=True)

class Placement(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    client_id = db.Column(db.Integer, db.ForeignKey('client.id'), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    interest_rate = db.Column(db.Float, nullable=False)
    interest_type = db.Column(db.String(20), default='Simple')
    tenure_months = db.Column(db.Integer, nullable=False)
    start_date = db.Column(db.Date, default=datetime.utcnow)
    payment_frequency = db.Column(db.String(20), default='Monthly')
    commission_percentage = db.Column(db.Float, default=0.0)
    arrangement_fee = db.Column(db.Float, default=0.0)
    collateral = db.Column(db.String(255))
    
    # New fields for enhanced functionality
    current_balance = db.Column(db.Float, default=0.0)
    status = db.Column(db.String(20), default='Active')  # Active, Partially Liquidated, Fully Liquidated
    last_interest_calculation = db.Column(db.Date)
    placement_number = db.Column(db.String(20), unique=True, nullable=False)
    interest_payment_frequency = db.Column(db.String(20), nullable=True)
    payment_frequency_months = db.Column(db.Integer, nullable=True)

    due_date = db.Column(db.Date, nullable=False)
    interest_due = db.Column(db.Float, nullable=False, default=0.0)
    principal_due = db.Column(db.Float, default=0.0)
    total_due = db.Column(db.Float, nullable=False, default=0.0)
    is_paid = db.Column(db.Boolean, default=False)

    schedules = db.relationship('PlacementSchedule', back_populates='placement', cascade='all, delete-orphan')
   
    def calculate_daily_interest(self, as_of_date=None):
        if as_of_date is None:
            as_of_date = date.today()

        # Default to start_date if last_interest_calculation is not set
        from_date = self.last_interest_calculation or self.start_date
        if not from_date:
            return 0.0

        if self.current_balance is None or self.interest_rate is None:
            return 0.0

        days = (as_of_date - from_date).days
        daily_rate = self.interest_rate / 36500
        return round(self.current_balance * daily_rate * days, 2)

    
    def monthly_interest(self):
        if self.current_balance is None or self.interest_rate is None:
            return 0.0
        return self.current_balance * (self.interest_rate / 1200)
    
    def accrued_interest(self):
        try:
            return self.calculate_daily_interest()
        except Exception:
            return 0.0


    def add_deposit(self, amount, deposit_date=None):
        """Add additional funds to the placement"""
        if not deposit_date:
            deposit_date = datetime.utcnow().date()
            
        # Capitalize accrued interest before deposit
        self.capitalize_interest(deposit_date)
        
        # Add deposit to balance
        self.current_balance += float(amount)
        self.amount += float(amount)  # Also update the original amount
        self.last_interest_calculation = deposit_date
        
        # Record transaction
        transaction = PlacementTransaction(
            placement_id=self.id,
            transaction_date=deposit_date,
            amount=amount,
            transaction_type='Deposit',
            description=f"Additional deposit: ${amount:,.2f}"
        )
        db.session.add(transaction)
    
    def withdraw_funds(self, amount, withdrawal_date=None):
        """Withdraw funds from the placement"""
        if not withdrawal_date:
            withdrawal_date = datetime.utcnow().date()
            
        # Capitalize accrued interest before withdrawal
        self.capitalize_interest(withdrawal_date)
        
        # Check sufficient funds
        if amount > self.current_balance:
            raise ValueError("Withdrawal amount exceeds available balance")
        
        # Process withdrawal
        self.current_balance -= float(amount)
        self.last_interest_calculation = withdrawal_date
        
        # Update status
        if self.current_balance <= 0.01:  # Account for floating point precision
            self.status = 'Fully Liquidated'
        else:
            self.status = 'Partially Liquidated'
        
        # Record transaction
        transaction = PlacementTransaction(
            placement_id=self.id,
            transaction_date=withdrawal_date,
            amount=-amount,
            transaction_type='Withdrawal',
            description=f"Withdrawal: ${amount:,.2f}"
        )
        db.session.add(transaction)
        
        return self.current_balance
    
    def change_interest_rate(self, new_rate, effective_date=None):
        """Change the interest rate for the placement"""
        if not effective_date:
            effective_date = datetime.utcnow().date()
            
        # Capitalize accrued interest before rate change
        self.capitalize_interest(effective_date)
        
        # Update rate
        self.interest_rate = new_rate
        self.last_interest_calculation = effective_date
        
        # Record transaction
        transaction = PlacementTransaction(
            placement_id=self.id,
            transaction_date=effective_date,
            amount=0,
            transaction_type='RateChange',
            description=f"Rate changed to {new_rate}%"
        )
        db.session.add(transaction)
    
    def capitalize_interest(self, as_of_date=None):
        """Capitalize accrued interest into principal"""
        if not as_of_date:
            as_of_date = datetime.utcnow().date()
            
        # Calculate and capitalize interest
        interest = self.calculate_daily_interest(as_of_date)
        if interest > 0:
            self.current_balance += interest
            self.last_interest_calculation = as_of_date
            
            # Record transaction
            transaction = PlacementTransaction(
                placement_id=self.id,
                transaction_date=as_of_date,
                amount=interest,
                transaction_type='Interest',
                description=f"Interest capitalization: ${interest:,.2f}"
            )
            db.session.add(transaction)
            return interest
        return 0.0
    
    def liquidate(self, liquidation_date=None):
        """Fully liquidate the placement"""
        if not liquidation_date:
            liquidation_date = datetime.utcnow().date()
            
        # Capitalize final interest
        self.capitalize_interest(liquidation_date)
        
        # Withdraw remaining balance
        final_balance = self.current_balance
        self.withdraw_funds(final_balance, liquidation_date)
        self.status = 'Fully Liquidated'
        
        return final_balance
    
    def accrued_interest(self, as_of_date=None):
        """Calculate accrued interest not yet capitalized"""
        if not as_of_date:
            as_of_date = datetime.utcnow().date()
        return self.calculate_daily_interest(as_of_date)
    

    @property
    def maturity_date(self):
        if self.start_date and self.tenure_months:
            return self.start_date + timedelta(days=30 * self.tenure_months)
        return None

    @property
    def next_interest_date(self):
        if self.last_interest_calculation:
            return self.last_interest_calculation + timedelta(days=30)
        return None

    def change_tenure(self, new_tenure, effective_date):
        self.tenure_months = new_tenure
        self.due_date = self.start_date + relativedelta(months=new_tenure)

        # Log transaction
        transaction = PlacementTransaction(
            placement_id=self.id,
            transaction_type='Tenure Change',
            amount=0.0,
            description=f'Tenure changed to {new_tenure} months, effective {effective_date.strftime("%Y-%m-%d")}'
        )
        db.session.add(transaction)
        db.session.commit()

        # Optionally regenerate the schedule
        new_schedule = generate_placement_schedule(self)
        if new_schedule:
            # Delete old unpaid schedules first
            PlacementSchedule.query.filter_by(placement_id=self.id, is_paid=False).delete()
            db.session.bulk_save_objects(new_schedule)

class ReconciliationReport(db.Model):
    __tablename__ = 'reconciliation_reports'
    
    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.Date, default=date.today)
    level = db.Column(db.String(20), nullable=False)  # 'payroll', 'cash'
    total_expected = db.Column(db.Float, default=0.0)
    total_received = db.Column(db.Float, default=0.0)
    discrepancy_count = db.Column(db.Integer, default=0)
    details = db.Column(db.Text)  # JSON string of discrepancies
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f'<ReconciliationReport {self.date} ({self.level}): {self.discrepancy_count} discrepancies>'


class PayrollDeduction(db.Model):
    __tablename__ = 'payroll_deductions'
    __table_args__ = (
        db.Index('idx_payroll_loan_id', 'loan_id'),
        db.Index('idx_payroll_schedule_id', 'schedule_id'),
    )

    id = db.Column(db.Integer, primary_key=True)
    loan_id = db.Column(db.Integer, db.ForeignKey('loan_applications.id'), nullable=False)
    schedule_id = db.Column(db.Integer, db.ForeignKey('repayment_schedules.id'), nullable=True)
    vote_id = db.Column(db.Integer, db.ForeignKey('votes.id'), nullable=True)
    amount = db.Column(db.Float, default=0.0)
    deduction_date = db.Column(db.Date, nullable=False)
    batch_id = db.Column(db.String(50), nullable=True)  # Links to batch upload
    status = db.Column(db.String(20), default='processed')  # 'processed', 'failed'
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    loan = db.relationship('LoanApplication', backref='payroll_deductions')
    schedule = db.relationship('RepaymentSchedule', backref='payroll_deductions')
    vote = db.relationship('Vote', backref='payroll_deductions')

    def __repr__(self):
        return f'<PayrollDeduction Loan {self.loan_id}: {self.amount:.2f} on {self.deduction_date}>'
    
class CashReceipt(db.Model):
    __tablename__ = 'cash_receipts'
    __table_args__ = (
        db.Index('idx_cash_vote_id', 'vote_id'),
    )

    id = db.Column(db.Integer, primary_key=True)
    vote_id = db.Column(db.Integer, db.ForeignKey('votes.id'), nullable=True)
    amount = db.Column(db.Float, default=0.0)
    receipt_date = db.Column(db.Date, nullable=False)
    batch_id = db.Column(db.String(50), nullable=True)  # Links to batch upload
    status = db.Column(db.String(20), default='processed')  # 'processed', 'failed'
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    vote = db.relationship('Vote', backref='cash_receipts')

    def __repr__(self):
        return f'<CashReceipt Vote {self.vote_id}: {self.amount:.2f} on {self.receipt_date}>'

# New model for transaction history
class PlacementTransaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    placement_id = db.Column(db.Integer, db.ForeignKey('placement.id'), nullable=False)
    transaction_date = db.Column(db.Date, default=datetime.utcnow)
    amount = db.Column(db.Float, nullable=False)
    transaction_type = db.Column(db.String(20), nullable=False)  # Deposit, Withdrawal, Interest, RateChange
    description = db.Column(db.String(255))

class PlacementSchedule(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    placement_id = db.Column(db.Integer, db.ForeignKey('placement.id'), nullable=True)
    due_date = db.Column(db.Date, nullable=False)
    interest_due = db.Column(db.Float, default=0.0)
    principal_due = db.Column(db.Float, default=0.0)  # ← ADD THIS
    total_due = db.Column(db.Float, default=0.0)
    is_paid = db.Column(db.Boolean, default=False)

    placement = db.relationship('Placement', back_populates='schedules')

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

from flask_wtf import FlaskForm
from wtforms import (
    StringField, SubmitField, FloatField,
    IntegerField, SelectField, DateField
)
from wtforms.validators import DataRequired, Email, NumberRange, Optional
from datetime import datetime
from wtforms.validators import DataRequired, NumberRange, Optional, Email

# ==============================
# Client Form
# ==============================
class ClientForm(FlaskForm):
    full_name = StringField("Full Name", validators=[DataRequired()])
    national_id = StringField("National ID", validators=[DataRequired()])
    phone = StringField("Phone", validators=[Optional()])
    email = StringField("Email", validators=[Optional(), Email()])
    submit = SubmitField("Save Client")

# ==============================
# Placement Form
# ==============================
from flask_wtf import FlaskForm
from wtforms.validators import DataRequired, NumberRange, Optional, Email
from wtforms import StringField, DecimalField, IntegerField, SelectField, DateField, FloatField, IntegerField, SubmitField

class PlacementForm(FlaskForm):
    client_id = SelectField("Client", coerce=int, validators=[DataRequired()])
    amount = FloatField("Amount", validators=[DataRequired(), NumberRange(min=0.01)])
    interest_rate = FloatField("Interest Rate (%)", validators=[DataRequired(), NumberRange(min=0)])
    
    interest_type = SelectField(
        "Interest Type",
        choices=[("Simple", "Simple"), ("Compound", "Compound")],
        validators=[DataRequired()]
    )
    
    tenure_months = IntegerField("Tenure (Months)", validators=[DataRequired(), NumberRange(min=1)])
    start_date = DateField("Start Date", format="%Y-%m-%d", validators=[DataRequired()])


    payment_frequency_months = IntegerField(
        "Payment Frequency (Months)",
        validators=[DataRequired()],
        default=1
    )

    commission_percentage = FloatField("Commission to RM (%)", default=0.0, validators=[Optional()])
    arrangement_fee = FloatField("Arrangement Fee", default=0.0, validators=[Optional()])
    collateral = StringField("Collateral Info", validators=[Optional()])
    
    submit = SubmitField("Create Placement")


# ==============================
# Deposit Form
# ==============================
class DepositForm(FlaskForm):
    amount = FloatField("Amount", validators=[DataRequired(), NumberRange(min=0.01)])
    transaction_date = DateField("Transaction Date", default=datetime.utcnow, validators=[DataRequired()])
    submit = SubmitField("Add Deposit")

# ==============================
# Withdrawal Form
# ==============================
class WithdrawalForm(FlaskForm):
    amount = FloatField("Amount", validators=[DataRequired(), NumberRange(min=0.01)])
    transaction_date = DateField("Transaction Date", default=datetime.utcnow, validators=[DataRequired()])
    submit = SubmitField("Process Withdrawal")

# ==============================
# Rate Change Form
# ==============================
class RateChangeForm(FlaskForm):
    new_rate = FloatField("New Interest Rate (%)", validators=[DataRequired(), NumberRange(min=0)])
    effective_date = DateField("Effective Date", default=datetime.utcnow, validators=[DataRequired()])
    submit = SubmitField("Change Rate")

# ==============================
# Capitalize Interest Form
# ==============================
class CapitalizeForm(FlaskForm):
    transaction_date = DateField("Transaction Date", default=datetime.utcnow, validators=[DataRequired()])
    submit = SubmitField("Capitalize Interest")

# ==============================
# Liquidate Placement Form
# ==============================
class LiquidateForm(FlaskForm):
    transaction_date = DateField("Transaction Date", default=datetime.utcnow, validators=[DataRequired()])
    submit = SubmitField("Liquidate Placement")

from flask_wtf import FlaskForm
from wtforms import (
    SelectField,
    DecimalField,
    IntegerField,
    DateField,
    StringField,
    SubmitField
)
from wtforms.validators import DataRequired, Optional, NumberRange
from datetime import date

class PlacementUpdateForm(FlaskForm):
    amount = DecimalField("Amount (positive = deposit, negative = withdrawal)", places=2, validators=[Optional()])
    new_interest_rate = DecimalField("New Interest Rate (%)", places=2, validators=[Optional()])
    new_tenure_months = IntegerField("New Tenure (Months)", validators=[Optional()])
    new_payment_frequency = IntegerField("New Payment Frequency (Months)", validators=[Optional()])
    
    effective_date = DateField("Effective Date", format="%Y-%m-%d", validators=[DataRequired()])
    transaction_date = DateField("Transaction Date", default=date.today, validators=[DataRequired()])
    description = StringField("Description", validators=[Optional()])

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

def regenerate_schedule(self):
    PlacementSchedule.query.filter_by(placement_id=self.id).delete()
    schedule = generate_placement_schedule(self)
    db.session.bulk_save_objects(schedule)

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
def save_document(file, customer_id, doc_type):
    """Save uploaded document to filesystem and return (filename, filepath)"""
    if not file or file.filename == '':
        return None, None
        
    try:
        # Create secure filename
        filename = secure_filename(file.filename)
        unique_filename = f"{customer_id}_{int(time.time())}_{filename}"
        
        # Get absolute upload path
        upload_folder = os.path.abspath(app.config['UPLOAD_FOLDER'])
        
        # Ensure directory exists
        os.makedirs(upload_folder, exist_ok=True)
        
        # Save file
        filepath = os.path.join(upload_folder, unique_filename)
        file.save(filepath)
        
        # Return relative path for database storage
        relative_path = os.path.relpath(filepath, start=app.root_path)
        return unique_filename, relative_path
        
    except Exception as e:
        app.logger.error(f"Error saving document: {str(e)}")
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

def notify_client(client, message):
    print(f"📲 SMS to {client.phone}: {message}")
    # Use Twilio here

def notify_rm(rm, message):
    print(f"📧 Email to {rm.email}: {message}")
    # Use Flask-Mail or SMTP

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

@app.route('/admin/dashboard', methods=['GET', 'POST'])
@login_required
def admin_dashboard():
    if current_user.role.name != 'admin':
        abort(403)
    
    # Moved to top: Get section parameter first with default value
    section = request.args.get('section', 'users')  # Default to 'users'

    form = RecipientForm()
    recent_recipients = []

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
    
    elif section == 'sales_report':
        # Pre-populate only on GET
        if request.method == 'GET':
            last_notification = Notification.query.filter(
                Notification.email_recipients.isnot(None)
            ).order_by(Notification.timestamp.desc()).first()
            if last_notification:
                form.emails.data = last_notification.email_recipients
                form.subject.data = last_notification.email_subject

        recent_recipients = Notification.query.filter(
            Notification.email_recipients.isnot(None)
        ).order_by(Notification.timestamp.desc()).limit(5).all()

        if form.validate_on_submit():
            app.logger.info(f"Sending email to: {form.emails.data}")
            recipients = [email.strip() for email in form.emails.data.split(',')]
            success = send_sales_notification_email(
                recipients=recipients,
                custom_message=form.message.data
            )

            if success:
                flash('Report sent successfully!', 'success')
            else:
                flash('Failed to send report', 'danger')

            return redirect(url_for('admin_dashboard', section='sales_report'))

        return render_template(
            'admin_dashboard.html',
            section=section,
            users=[],
            roles=[],
            cutoff_configs={},
            configs_by_category={},
            categories=[],
            terms=[],
            form=form,
            recent_recipients=recent_recipients
        )

    # Default section: users
    users = User.query.all()
    roles = Role.query.all()
    return render_template(
        'admin_dashboard.html',
        section=section,
        users=users,
        roles=roles,
        cutoff_configs=cutoff_configs,
        configs_by_category={},
        categories=[],
        terms=[],
        form=None,
        recent_recipients=[]
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

    notifications = Notification.query.filter(
            Notification.recipient_id == None,
            Notification.is_read.is_(False)
        ).order_by(Notification.timestamp.desc())
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

def generate_placement_schedule(placement):
    rate = placement.interest_rate / 100
    principal = placement.amount
    frequency = placement.repayment_frequency_days
    total_days = placement.tenure_months * 30  # approx.
    num_payments = total_days // frequency

    for i in range(1, num_payments + 1):
        due_date = placement.start_date + timedelta(days=i * frequency)

        if placement.interest_type == 'Simple':
            interest = (principal * rate * frequency) / 365
        else:  # Compound
            interest = principal * ((1 + rate / 365) ** frequency - 1)

        schedule = PlacementSchedule(
            placement_id=placement.id,
            due_date=due_date,
            interest_due=round(interest, 2)
        )
        db.session.add(schedule)

    db.session.commit()


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

@app.route('/customer/enquiry', methods=['POST'])
@login_required
@role_required('admin')
def customer_enquiry():
    query_form = CustomerQueryForm()

    if not query_form.validate_on_submit():
        flash('Invalid input', 'danger')
        return redirect(url_for('register_customer'))

    national_id = query_form.national_id.data
    employment_number = query_form.employment_number.data
    section = request.form.get('section', 'topup')

    if not national_id and not employment_number:
        flash('Please provide National ID or Employment Number', 'danger')
        return redirect(url_for('register_customer'))

    # Build dynamic query
    filters = []
    if national_id:
        filters.append(Customer.national_id == national_id)
    if employment_number:
        filters.append(Customer.employment_number == employment_number)

    customer = Customer.query.filter(*filters).first()

    if not customer:
        flash('Customer not found', 'danger')
        return redirect(url_for('register_customer'))

    flash(f'Customer found: {customer.first_name} {customer.last_name}', 'success')

    return redirect(url_for(
        'customer_account',
        file_number=customer.file_number,  # REQUIRED path variable
        employment_number=customer.employment_number or 'PLACEHOLDER',
        national_id=customer.national_id or 'PLACEHOLDER',
        section=section
    ))


from flask import request

@app.route('/customer/<file_number>/account')
@login_required
@role_required('admin')
def customer_account(file_number: str):
    try:
        # Retrieve optional query parameters
        employment_number = request.args.get('employment_number')
        national_id = request.args.get('national_id')
        section = request.args.get('section', 'statement')

        customer = Customer.query.filter_by(file_number=file_number).first_or_404()

        agents = Agent.query.filter_by(active=True).order_by(Agent.name).all()
        team_leaders = Agent.query.filter_by(role="Team Leader").all()

        loans = (
            LoanApplication.query
            .options(joinedload(LoanApplication.payments).joinedload(Payment.allocations))
            .filter(LoanApplication.customer_id == customer.id)
            .all()
        )

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
                for a in p.allocations:
                    if a.principal:
                        remaining_balance -= a.principal
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

            if loan.status == 'closed' or loan.loan_state == 'settled_client':
                return {
                    'capitalized_amount': capitalized,
                    'current_balance': 0.0,
                    'top_up_balance': 0.0,
                    'settlement_balance': 0.0,
                    'top_up_interest': 0.0,
                    'settlement_interest': 0.0,
                }

            return {
                'capitalized_amount': capitalized,
                'current_balance': current_balance,
                'top_up_balance': round(current_balance + projected_interest(3), 2),
                'settlement_balance': round(current_balance + projected_interest(6), 2),
                'top_up_interest': projected_interest(3),
                'settlement_interest': projected_interest(6),
            }

        statement = []
        for loan in loans:
            balances = calculate_balances(loan)
            running_balance_display = balances.get('capitalized_amount', 0.0)

            for payment in sorted(loan.payments, key=lambda p: p.created_at):
                for allocation in payment.allocations:
                    principal = allocation.principal or 0
                    interest = allocation.interest or 0
                    fees = allocation.fees or 0

                    running_balance_display -= principal
                    running_balance_display = max(running_balance_display, 0)

                    allocated_total = principal + interest + fees
                    valid_allocation = abs(allocated_total - payment.amount) < 0.01

                    statement.append({
                        'id': payment.id,
                        'date': payment.created_at.strftime('%Y-%m-%d'),
                        'total': payment.amount,
                        'principal': principal,
                        'interest': interest,
                        'collection_fees': fees,
                        'remaining_balance': round(running_balance_display, 2),
                        'method': payment.method,
                        'reference': payment.reference,
                        'valid_allocation': valid_allocation
                    })

            loan.capitalized_amount = balances.get('capitalized_amount', 0.0)
            loan.current_balance = balances.get('current_balance', 0.0)
            loan.top_up_balance = balances.get('top_up_balance', 0.0)
            loan.settlement_balance = balances.get('settlement_balance', 0.0)
            loan.top_up_interest = balances.get('top_up_interest', 0.0)
            loan.settlement_interest = balances.get('settlement_interest', 0.0)
            loan.cash_to_client = round(loan.loan_amount - loan.top_up_balance, 2) if loan.loan_state == 'active' else loan.loan_amount

        return render_template(
            'customer_account.html',
            customer=customer,
            loans=loans,
            agents=agents,
            team_leaders=team_leaders,
            statement=statement,
            section=section,
            employment_number=employment_number,
            national_id=national_id
        )

    except Exception as e:
        app.logger.error(f"Account view error: {str(e)}")
        flash("Error loading account details", "danger")
        return redirect(url_for('home'))


from datetime import date

@app.route('/loan/<loan_number>/statement')
def loan_statement(loan_number):
    try:
        loan = (
            LoanApplication.query
            .options(
                db.joinedload(LoanApplication.customer),
                db.joinedload(LoanApplication.payments).joinedload(Payment.allocations)
            )
            .filter_by(loan_number=loan_number)
            .first_or_404()
        )

        config = get_pricing_config(loan.category, loan.term_months, loan)
        loan_amount = loan.loan_amount or 0

        capitalized_amount = (
            loan_amount +
            (loan_amount * config.get('origination', 0)) +
            (loan_amount * config.get('insurance', 0)) +
            config.get('crb', 0)
        )

        monthly_rate = config.get('rate', 0)
        term = loan.term_months or 0

        # Compute current balance
        if loan.status == 'closed' or loan.loan_state == 'settled_client':
            current_balance = 0.0
            payments_made = 0
        else:
            running_balance = capitalized_amount
            payments_made = 0
            for payment in sorted(loan.payments, key=lambda p: p.created_at):
                for allocation in payment.allocations:
                    running_balance -= allocation.principal or 0
                running_balance = max(running_balance, 0)
                payments_made += 1
            current_balance = round(running_balance, 2)

        remaining_term = max(term - payments_made, 0)

        # Calculate annuity
        if monthly_rate > 0 and term > 0:
            annuity_factor = (
                monthly_rate * (1 + monthly_rate) ** term
            ) / ((1 + monthly_rate) ** term - 1)
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

        if current_balance > 0:
            top_up_balance = round(current_balance + calculate_projected_interest(3), 2)
            settlement_balance = round(current_balance + calculate_projected_interest(6), 2)
        else:
            top_up_balance = settlement_balance = 0.0

        # Build statement
        statement = []
        running_balance_display = capitalized_amount

        for payment in sorted(loan.payments, key=lambda p: p.created_at):
            is_top_up = payment.method.lower() == 'top_up'

            for allocation in payment.allocations:
                principal = allocation.principal or 0
                interest = allocation.interest or 0
                fees = allocation.fees or 0

                # If this is a top-up payment, it clears the balance
                if is_top_up:
                    running_balance_display = 0.0
                else:
                    running_balance_display -= principal
                    running_balance_display = max(running_balance_display, 0)

                allocated_total = principal + interest + fees
                valid_allocation = abs(allocated_total - payment.amount) < 0.01

                statement.append({
                    'id': payment.id,
                    'date': payment.created_at.strftime('%Y-%m-%d'),
                    'total': payment.amount,
                    'principal': principal,
                    'interest': interest,
                    'collection_fees': fees,
                    'remaining_balance': round(running_balance_display, 2),
                    'method': payment.method,
                    'reference': payment.reference,
                    'valid_allocation': valid_allocation
                })

        totals = {
            'paid': sum(p.amount for p in loan.payments),
            'principal': sum(a.principal or 0 for p in loan.payments for a in p.allocations),
            'interest': sum(a.interest or 0 for p in loan.payments for a in p.allocations),
            'fees': sum(a.fees or 0 for p in loan.payments for a in p.allocations)
        }

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

@app.route("/admin/customer/<file_number>/")
@login_required
@role_required('admin')
def admin_customer_redirect(file_number):
    return redirect(url_for('customer_account', file_number=file_number))


def redirect_to_customer(customer):
    identifier = customer.file_number if customer.file_number else customer.id
    return redirect(url_for('customer_details', identifier=identifier))

@app.route("/debug/routes")
def debug_routes():
    routes = []
    for rule in app.url_map.iter_rules():
        routes.append(str(rule))
    return "<br>".join(routes)

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
@login_required
def view_document(doc_id):
    """Serve a document file with proper security checks"""
    try:
        # Retrieve document with existence check
        doc = Document.query.get(doc_id)
        if not doc:
            app.logger.warning(f"Document not found: {doc_id}")
            abort(404, description="Document not found")
        
        # Get absolute path with fallbacks
        abs_path = doc.absolute_path
        if not abs_path:
            app.logger.error(f"Document path missing: {doc_id}")
            abort(404, description="Document path not configured")
        
        # Verify file exists
        if not os.path.exists(abs_path):
            app.logger.error(f"Document file missing: {abs_path}")
            abort(404, description="Document file not found")
        
        # Determine MIME type
        mime_type, _ = mimetypes.guess_type(doc.filename)
        if not mime_type:
            # Fallback for common types
            if doc.filename.lower().endswith('.pdf'):
                mime_type = 'application/pdf'
            elif doc.filename.lower().endswith(('.png', '.jpg', '.jpeg')):
                mime_type = 'image/' + doc.filename.split('.')[-1].lower()
            else:
                mime_type = 'application/octet-stream'
        
        # Send file with security headers
        response = send_file(
            abs_path,
            mimetype=mime_type,
            as_attachment=False,
            conditional=True
        )
        
        # Security headers
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['Content-Disposition'] = f'inline; filename="{doc.filename}"'
        
        return response
        
    except Exception as e:
        app.logger.exception(f"Error serving document {doc_id}: {str(e)}")
        abort(500, description="Internal server error")

def convert_legacy_paths():
    """Convert any existing paths to the new relative format"""
    docs = Document.query.all()
    updated = 0
    
    for doc in docs:
        if doc.path and os.path.isabs(doc.path):
            try:
                doc.path = os.path.relpath(doc.path, start=app.root_path)
                updated += 1
            except ValueError:
                continue
    
    if updated:
        db.session.commit()
    
    return updated

@app.route('/register', methods=['GET', 'POST'])
@role_required("sales_ops", "admin")
def register_customer_debug():
    agents = Agent.query.filter_by(active=True).order_by(Agent.name).all()
    team_leaders = Agent.query.filter_by(role="Team Leader").all()
    query_form = CustomerQueryForm()

    if request.method == 'POST':
        file = request.files.get('csv_file')
        try:
            if file and file.filename.endswith('.csv'):
                stream = io.StringIO(file.stream.read().decode("UTF8"), newline=None)
                for row in csv.DictReader(stream):
                    process_customer_registration(row)
                flash("✅ CSV upload processed successfully.", "success")
            else:
                process_customer_registration(request.form, files=request.files)
                flash("✅ Customer and loan registered successfully.", "success")
        except Exception as e:
            db.session.rollback()
            flash(f"❌ Error: {str(e)}", "danger")

        return redirect(url_for('register_customer_debug'))

    return render_template(
        'register_customer_debug.html',
        agents=agents,
        team_leaders=team_leaders,
         query_form=query_form
    )


def process_customer_registration(data, files=None):
    try:
        loan_amount = max(float(data.get('loan_amount', 0)), 0.0)
    except (TypeError, ValueError):
        raise Exception("Invalid loan amount.")

    # Loan category setup
    category_code = int(data.get('loan_category'))
    CATEGORY_MAP = {
        1: {'prefix': '1', 'label': 'civil_servant'},
        2: {'prefix': '2', 'label': 'private_sector'},
        3: {'prefix': '3', 'label': 'sme'}
    }
    category_info = CATEGORY_MAP.get(category_code)
    if not category_info:
        raise Exception("Invalid loan category selected.")

    term_months = int(data.get('loan_term', 0))
    config = get_pricing_config(category_info['label'], term_months)
    if not config:
        raise Exception("Invalid loan term selected.")

    # Validate DOB
    dob = datetime.strptime(data['dob'], "%Y-%m-%d").date()
    today = date.today()
    age = today.year - dob.year - ((today.month, today.day) < (dob.month, dob.day))
    if age < 16:
        raise Exception("Customer must be at least 16 years old.")
    if age + (term_months // 12) > 60:
        raise Exception("Loan tenure will exceed retirement age (60 years).")

    # Validate employment start date
    date_joined = data.get("date_joined")
    if date_joined:
        date_joined = datetime.strptime(date_joined, "%Y-%m-%d").date()
        years_in_service = today.year - date_joined.year - ((today.month, today.day) < (date_joined.month, date_joined.day))
        if years_in_service >= 20:
            flash("⚠️ Customer may be eligible for voluntary retirement.", "warning")

    # Pricing fees
    crb_fees = 3000
    origination_fees = loan_amount * config['origination']
    insurance_fees = loan_amount * config['insurance']
    collection_fees = loan_amount * config['collection']
    capitalized_amount = loan_amount + origination_fees + insurance_fees + crb_fees

    # Calculate monthly repayment
    r = config['rate']
    annuity = (r * (1 + r) ** term_months) / ((1 + r) ** term_months - 1)
    monthly_payment = (capitalized_amount * annuity) + collection_fees

    # Check if customer already exists
    existing_customer = Customer.query.filter(
        (Customer.email == data['email']) |
        (Customer.national_id == data['national_id'])
    ).first()

    if existing_customer:
        customer = existing_customer
    else:
        # Generate customer file number
        now = datetime.utcnow()
        file_number = f"{now.year}{now.month:02d}{db.session.query(Customer).count() + 1:06d}"

        agent_id = int(data['agent_id']) if data.get('agent_id') else None

        # Create customer record
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
            agent_id=agent_id,
            maker_id=current_user.id
        )
        db.session.add(customer)
        db.session.flush()

        # Attach documents for new customers
        document_fields = {
            'national_id_front': 'id_front',
            'form': 'form',
            'customer_photo': 'photo',
            'payslip': 'payslip',
            'bank_statement': 'bank_statement',
            'letter_of_undertaking': 'undertaking_letter'
        }
        for field, dtype in document_fields.items():
            if files and (file := files.get(field)) and file.filename:
                filename, path = save_document(file, customer.id, dtype)
                db.session.add(Document(
                    customer_id=customer.id,
                    filename=filename,
                    filetype=dtype,
                    path=path
                ))

    # Loan number generation
    loan_number = f"{category_info['prefix']}{str(term_months).zfill(2)}{db.session.query(LoanApplication).count() + 1:06d}"

    # Top-up balance if applicable
    previous = LoanApplication.query.filter_by(customer_id=customer.id).order_by(LoanApplication.id.desc()).first()
    top_up_balance = calculate_balances(previous).get('top_up_balance', 0) if previous else 0
    cash_to_client = max(loan_amount - top_up_balance, 0)

    agent_id = request.form.get("agent_id")
    agent_id = int(agent_id) if agent_id and agent_id.isdigit() else current_user.id
    # Create loan record
    loan = LoanApplication(
        customer_id=customer.id,
        loan_amount=loan_amount,
        term_months=term_months,
        monthly_instalment=round(monthly_payment, 2),
        total_repayment=round(monthly_payment * term_months, 2),
        effective_rate=calculate_eir(loan_amount, term_months, config),
        category=category_info['label'],
        loan_category=category_code,
        loan_number=loan_number,
        file_number=customer.file_number if existing_customer else file_number,
        application_status='pending',
        loan_state='application',
        performance_status='pending',
        crb_fees=crb_fees,
        agent_id=agent_id,
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

    db.session.add(Disbursement(
        loan_id=loan.id,
        amount=cash_to_client,
        method='bank',
        status='pending',
        reference=f"Initial disbursement for {loan.loan_number}"
    ))

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

                # Only create a loan if customer doesn't already have one
                if not customer.loans:
                    loan = LoanApplication(
                        customer_id=customer.id,
                        loan_amount=customer.amount_requested or 0.0,
                        loan_category="SME",  # You can make dynamic
                        status='pending',
                        loan_state='Active',
                        application_status='awaiting_approval',
                        vote_id=vote.id
                    )
                    db.session.add(loan)
                    db.session.flush()

                    # ✅ Link customer documents to this new loan
                    for doc in customer.customer_documents:
                        doc.loan_id = loan.id

                    approved_count += 1

                else:
                    for loan in customer.loans:
                        loan.status = 'pending'
                        loan.vote_id = vote.id

                        for doc in customer.customer_documents:
                            if not doc.loan_id:
                                doc.loan_id = loan.id

                    approved_count += 1

            db.session.commit()
            flash(f"{approved_count} customer(s) approved with vote assignments!", "success")
        else:
            flash("No customers selected.", "warning")
        return redirect(url_for('approve_customers'))

    # GET
    unapproved_customers = Customer.query \
        .options(joinedload(Customer.customer_documents)) \
        .filter_by(is_approved_for_creation=False) \
        .all()

    active_votes = Vote.query.filter_by(is_active=True).order_by(Vote.code.asc()).all()
    if not active_votes:
        active_votes = Vote.query.order_by(Vote.code.asc()).all()

    return render_template('approve_customers.html',
                           customers=unapproved_customers,
                           votes=active_votes)

# Renders the admin approval dashboard
# Route for the approval dashboard
@app.route('/admin/approval_dashboard')
@login_required
def admin_approval_dashboard():
    # Query for pending customers
    pending_customers = Customer.query.filter_by(is_approved_for_creation=False).all()
    
    # Add pending loan count to each customer
    for customer in pending_customers:
        customer.pending_loans_count = LoanApplication.query.filter_by(
            customer_id=customer.id, 
            application_status='pending'
        ).count()
    
    return render_template(
        'admin_dashboard.html',  # or your template name
        section='approval',
        pending_customers=pending_customers
    )

def update_loan(loan, form_data):
    # Update basic loan attributes
    new_amount = form_data.get('loan_amount')
    new_term = form_data.get('term_months')
    new_cat = form_data.get('loan_category')

    if new_amount:
        loan.loan_amount = float(new_amount)
    if new_term:
        loan.term_months = int(new_term)
    if new_cat and new_cat.isdigit():
        loan.loan_category = int(new_cat)

    loan.application_status = form_data.get('application_status', loan.application_status)
    loan.loan_state = form_data.get('loan_state', loan.loan_state)

    # Update relationships
    vote_id = form_data.get('vote_id')
    agent_id = form_data.get('agent_id')
    loan.vote_id = int(vote_id) if vote_id and vote_id.isdigit() else None
    loan.agent_id = int(agent_id) if agent_id and agent_id.isdigit() else loan.agent_id

    # Recalculate pricing using the same method as registration
    CATEGORY_MAP = {
        1: 'civil_servant',
        2: 'private_sector',
        3: 'sme'
    }
    category_code = loan.loan_category or 1
    category_label = CATEGORY_MAP.get(category_code, 'civil_servant')
    config = get_pricing_config(category_label, loan.term_months)
    
    # Calculate new fees and payments
    crb_fees = 3000
    origination_fees = loan.loan_amount * config['origination']
    insurance_fees = loan.loan_amount * config['insurance']
    collection_fees = loan.loan_amount * config['collection']
    capitalized_amount = loan.loan_amount + origination_fees + insurance_fees + crb_fees
    
    # Calculate monthly payment
    r = config['rate']
    annuity = (r * (1 + r) ** loan.term_months) / ((1 + r) ** loan.term_months - 1)
    monthly_payment = (capitalized_amount * annuity) + collection_fees
    
    # Update loan financials
    loan.crb_fees = crb_fees
    loan.origination_fees = round(origination_fees, 2)
    loan.insurance_fees = round(insurance_fees, 2)
    loan.collection_fees = round(collection_fees, 2)
    loan.monthly_instalment = round(monthly_payment, 2)
    loan.total_repayment = round(monthly_payment * loan.term_months, 2)
    loan.cash_to_client = loan.loan_amount  # Simplified for edit flow
    loan.applied_interest_rate = config['rate']
    loan.applied_collection_fee = config['collection']
    loan.category = category_label

    # Handle disbursement
    completed_disb = Disbursement.query.filter(
        Disbursement.loan_id == loan.id,
        Disbursement.status.in_(["completed", "posted", "paid"])
    ).first()

    if not completed_disb:
        pending_disb = Disbursement.query.filter_by(
            loan_id=loan.id
        ).filter(
            Disbursement.status.in_(["pending", "scheduled"])
        ).first()

        if pending_disb:
            pending_disb.amount = loan.cash_to_client
            if not pending_disb.reference:
                pending_disb.reference = f"Initial disbursement for {loan.loan_number}"
        else:
            db.session.add(Disbursement(
                loan_id=loan.id,
                amount=loan.cash_to_client,
                method='bank',
                status='pending',
                reference=f"Initial disbursement for {loan.loan_number}"
            ))
    else:
        return "Disbursement already completed—amounts updated on the loan, but existing disbursement wasn’t altered."

    # Regenerate repayment schedule
    # First delete existing repayments
    RepaymentSchedule.query.filter_by(loan_id=loan.id).delete()
    db.session.flush()
    
    # Then generate new schedule
    loan.generate_repayment_schedule()

# Refactored route
@app.route('/loans/<int:loan_id>/edit', methods=['GET', 'POST'])
def edit_loan(loan_id):
    loan = LoanApplication.query.get_or_404(loan_id)
    agents = Agent.query.filter_by(active=True).order_by(Agent.name).all()
    votes = Vote.query.filter_by(is_active=True).order_by(Vote.code).all()

    if request.method == 'POST':
        try:
            warning = update_loan(loan, request.form)
            db.session.commit()
            
            if warning:
                flash(warning, "warning")
                flash('Loan updated with full recalculation! Disbursement not modified.', 'success')
            else:
                flash('Loan updated with full recalculation!', 'success')
                
            return redirect(url_for('view_loans'))
            
        except Exception as e:
            db.session.rollback()
            flash(f'Error updating loan: {str(e)}', 'danger')
            return redirect(request.url)

    return render_template('edit_loan.html', loan=loan, agents=agents, votes=votes)

# Route to handle approval
@app.route('/admin/admin_approval/<int:customer_id>', methods=['POST'])
@login_required
def admin_approval(customer_id):
    customer = Customer.query.get_or_404(customer_id)

    if not customer.is_approved_for_creation:
        customer.is_approved_for_creation = True
        customer.status = 'approved'

        # Approve all pending loans (no document check)
        pending_loans = LoanApplication.query.filter_by(
            customer_id=customer.id,
            application_status='pending'
        ).all()

        for loan in pending_loans:
            loan.application_status = 'approved'
            loan.loan_state = 'active'

        try:
            db.session.commit()
            flash(
                f"Customer {customer.first_name} {customer.last_name} and all pending loans approved.",
                "success"
            )
        except Exception as e:
            db.session.rollback()
            flash(f"Error during approval: {str(e)}", "error")

    return redirect(url_for('admin_approval_dashboard'))


@app.route('/customer/<int:customer_id>')
def view_customer(customer_id):
    customer = Customer.query.get_or_404(customer_id)
    return render_template('view_customer.html', customer=customer)

@app.route('/customer/<int:customer_id>/edit', methods=['GET', 'POST'])
@role_required("sales_ops", "admin")
def edit_customer(customer_id):
    customer = Customer.query.get_or_404(customer_id)

    if request.method == 'POST':
        try:
            customer.first_name = request.form['first_name']
            customer.last_name = request.form['last_name']
            customer.email = request.form['email']
            customer.contact = request.form.get('contact')
            customer.address = request.form.get('address')
            customer.employer = request.form.get('employer')
            customer.job_title = request.form.get('job_title')
            customer.salary = float(request.form.get('salary') or 0)
            customer.bank_name = request.form.get('bank_name')
            customer.bank_account = request.form.get('bank_account')
            customer.region = request.form.get('region')
            customer.district = request.form.get('district')
            # Add more fields as needed

            db.session.commit()
            flash("✅ Customer updated successfully.", "success")
            return redirect(url_for('view_customer'))
        except Exception as e:
            db.session.rollback()
            flash(f"❌ Error updating customer: {str(e)}", "danger")

    return render_template('edit_customer.html', customer=customer)

@app.route('/loans')
@login_required
def view_loans():
    # MODIFIED: Eager load all necessary data
    loans = db.session.query(LoanApplication, Customer) \
        .join(Customer, LoanApplication.customer_id == Customer.id) \
        .options(
            joinedload(LoanApplication.customer).load_only(Customer.first_name, Customer.last_name),
            joinedload(LoanApplication.documents),
            joinedload(LoanApplication.customer).joinedload(Customer.customer_documents)
        ) \
        .filter(Customer.is_approved_for_creation == True) \
        .filter(LoanApplication.application_status.in_(['pending', 'approved'])) \
        .all()

    # Combine documents and deduplicate
    processed_loans = []
    for loan, customer in loans:
        # Combine all documents
        all_docs = list(loan.documents) + list(customer.customer_documents)
        
        # Deduplicate by filename
        seen_filenames = set()
        unique_docs = []
        for doc in all_docs:
            if doc.filename not in seen_filenames:
                unique_docs.append(doc)
                seen_filenames.add(doc.filename)
        
        processed_loans.append({
            'loan': loan,
            'customer': customer,
            'unique_docs': unique_docs
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
                if not loan.repayment_schedule or len(loan.repayment_schedule) == 0:
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

        def calculate_capitalized_amount(loan_amount, config):
            try:
                origination = loan_amount * config.get('origination', 0)
                insurance = loan_amount * config.get('insurance', 0)
                crb = config.get('crb', 0)
                return round(loan_amount + origination + insurance + crb, 2)
            except Exception:
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

            # For closed & settled loans, balances are zero
            if loan.status == 'closed' and loan.loan_state == 'settled_client':
                return {
                    'capitalized_amount': capitalized,
                    'current_balance': 0.0,
                    'top_up_balance': 0.0,
                    'settlement_balance': 0.0,
                    'top_up_interest': 0.0,
                    'settlement_interest': 0.0,
                }

            return {
                'capitalized_amount': capitalized,
                'current_balance': current_balance,
                'top_up_balance': round(current_balance + projected_interest(3), 2),
                'settlement_balance': round(current_balance + projected_interest(6), 2),
                'top_up_interest': projected_interest(3),
                'settlement_interest': projected_interest(6),
            }

        processed_loans = []
        for loan in all_loans:
            customer = loan.customer
            balances = calculate_balances(loan)

            processed_loans.append({
                'customer': {
                    'first_name': customer.first_name,
                    'last_name': customer.last_name,
                    'file_number': customer.file_number
                },
                'loan': {
                    'loan_number': loan.loan_number,
                    'amount': loan.loan_amount or 0,
                    'term': loan.term_months,
                    'category': loan.category,
                    'monthly_instalment': loan.monthly_instalment,
                    'total_repayment': loan.total_repayment,
                    'balance': balances.get('current_balance', 0.0),
                    'disbursed': loan.disbursed,
                    'collection_fee': (loan.loan_amount or 0) * get_pricing_config(loan.category, loan.term_months, loan).get('collection', 0)
                },
                'fees': {
                    'crb': get_pricing_config(loan.category, loan.term_months, loan).get('crb', 0),
                    'origination': (loan.loan_amount or 0) * get_pricing_config(loan.category, loan.term_months, loan).get('origination', 0),
                    'insurance': (loan.loan_amount or 0) * get_pricing_config(loan.category, loan.term_months, loan).get('insurance', 0),
                    'total': (
                        get_pricing_config(loan.category, loan.term_months, loan).get('crb', 0)
                        + (loan.loan_amount or 0) * get_pricing_config(loan.category, loan.term_months, loan).get('origination', 0)
                        + (loan.loan_amount or 0) * get_pricing_config(loan.category, loan.term_months, loan).get('insurance', 0)
                    )
                },
                'balances': balances
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

from flask import request, send_file
from io import BytesIO
import pandas as pd
from datetime import datetime
from sqlalchemy import or_

@app.route("/reports")
def generate_report():
    # Get filters from query string
    search = request.args.get("search", "").lower()
    category = request.args.get("category", "")
    tenure = request.args.get("tenure", "")
    from_date = request.args.get("from")
    to_date = request.args.get("to")

    query = db.session.query(LoanApplication).join(Customer)

    # Apply filters
    if search:
        query = query.filter(
            or_(
                Customer.first_name.ilike(f"%{search}%"),
                Customer.last_name.ilike(f"%{search}%"),
                LoanApplication.application_status.ilike(f"%{search}%")
            )
        )
    if category:
        query = query.filter(LoanApplication.category == category)
    if tenure:
        query = query.filter(LoanApplication.term_months == int(tenure))
    if from_date:
        query = query.filter(LoanApplication.created_at >= datetime.fromisoformat(from_date))
    if to_date:
        query = query.filter(LoanApplication.created_at <= datetime.fromisoformat(to_date))

    loans = query.all()

    # Build dataframe
    rows = []
    for loan in loans:
        rows.append({
            "Loan Number": loan.loan_number,
            "File Number": loan.file_number,
            "Customer": f"{loan.customer.first_name} {loan.customer.last_name}",
            "Loan Amount": loan.loan_amount,
            "Term Months": loan.term_months,
            "Category": loan.category,
            "CRB Fee": loan.crb_fees,
            "Origination Fee": loan.origination_fees,
            "Insurance Fee": loan.insurance_fees,
            "Total Fees": loan.total_fees,
            "Collection Fees": loan.collection_fees,
            "Instalment": loan.monthly_instalment,
            "Total Repayment": loan.total_repayment,
            "Principal Balance": loan.balance,
            "Created At": loan.created_at.strftime("%Y-%m-%d"),
        })

    df = pd.DataFrame(rows)

    # Export to Excel in memory
    output = BytesIO()
    with pd.ExcelWriter(output, engine="xlsxwriter") as writer:
        df.to_excel(writer, index=False, sheet_name="Loan Book")

        # Add totals row
        worksheet = writer.sheets["Loan Book"]
        last_row = len(df) + 1
        worksheet.write(last_row, 0, "Totals")
        worksheet.write_formula(last_row, 3, f"=SUM(D2:D{last_row})")
        worksheet.write_formula(last_row, 6, f"=SUM(G2:G{last_row})")
        worksheet.write_formula(last_row, 7, f"=SUM(H2:H{last_row})")
        worksheet.write_formula(last_row, 8, f"=SUM(I2:I{last_row})")
        worksheet.write_formula(last_row, 9, f"=SUM(J2:J{last_row})")
        worksheet.write_formula(last_row, 10, f"=SUM(K2:K{last_row})")
        worksheet.write_formula(last_row, 11, f"=SUM(L2:L{last_row})")
        worksheet.write_formula(last_row, 12, f"=SUM(M2:M{last_row})")
        worksheet.write_formula(last_row, 13, f"=SUM(N2:N{last_row})")

    output.seek(0)

    filename = f"loan_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx"
    return send_file(output,
                     as_attachment=True,
                     download_name=filename,
                     mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")


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

    agent_id = request.form.get("agent_id")
    agent_id = int(agent_id) if agent_id and agent_id.isdigit() else current_user.id

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
        agent_id=agent_id,
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
        # --- Create payment for top-up balance ---
        payment = Payment(
            loan_id=base_loan.id,
            amount=top_up_balance,
            method='top_up',
            status='successful',
            reference=f"Top-Up from {loan_number}",
            created_at=datetime.utcnow()
        )
        db.session.add(payment)
        db.session.flush()

        # Allocate payment while loan is still open
        base_loan.allocate_payment(payment)

        # Commit so allocations are persisted
        db.session.commit()

        # Now close the base loan ONLY if fully paid
        if base_loan.top_up_balance <= 0 and (base_loan.top_up_interest or 0) <= 0:
            base_loan.status = 'closed'
            base_loan.loan_state = 'settled_client'
            base_loan.closure_type = 'topup'
            base_loan.closure_date = datetime.utcnow()

            # Cancel all remaining repayment schedules
            for schedule in base_loan.repayment_schedules:
                if schedule.status not in {"paid", "cancelled"}:
                    schedule.status = "cancelled"

            db.session.commit()



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

    agent_id = request.form.get("agent_id")
    agent_id = int(agent_id) if agent_id and agent_id.isdigit() else current_user.id

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
        agent_id=agent_id,
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

@app.context_processor
def inject_notifications():
    if not current_user.is_authenticated:
        return dict(notifications=[])
    
    try:
        unread = Notification.query.filter_by(
            recipient_id=current_user.id,
            is_read=False
        ).order_by(Notification.timestamp.desc()).all()
        return dict(notifications=unread)
    
    except ProgrammingError as e:
        # Handle missing column error specifically
        if "email_recipients" in str(e):
            current_app.logger.error("Notification schema mismatch, returning empty list")
            return dict(notifications=[])
        raise
    except Exception as e:
        current_app.logger.error(f"Unexpected error fetching notifications: {str(e)}")
        return dict(notifications=[])
    
    return dict(notifications=[])


def column_exists(cursor, table, column):
    cursor.execute("""
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = %s AND column_name = %s
    """, (table, column))
    return cursor.fetchone() is not None

def add_column(cursor, table, column, ddl):
    try:
        cursor.execute(f"ALTER TABLE {table} ADD COLUMN {column} {ddl}")
        print(f"✅  Added {table}.{column}")
    except Exception as e:
        print(f"❌  Failed to add {table}.{column}: {e}")

def check_db_schema():
    inspector = inspect(db.engine)
    cols = [c['name'] for c in inspector.get_columns('notifications')]
    assert 'email_recipients' in cols, "Missing notification columns"

def _parse_date(s, default):
    try:
        return datetime.strptime(s, '%Y-%m-%d').date()
    except (TypeError, ValueError):
        return default


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

    one_time, scheduled, event_based = _compute_income_db(start_date, end_date)

    categories = ['civil_servant', 'private_sector', 'sme']
    report = {cat: dict(origination=0, crb=0, insurance=0, collection=0, interest=0) for cat in categories}

    for row in one_time:
        if row.category in report:
            report[row.category]['origination'] += row.origination
            report[row.category]['crb'] += row.crb
            report[row.category]['insurance'] += row.insurance

    for row in scheduled:
        if row.category in report:
            report[row.category]['interest'] += row.interest
            report[row.category]['collection'] += row.collection

    for row in event_based:
        if row.category in report:
            total_event_interest = row.settlement_interest + row.top_up_interest
            report[row.category]['interest'] += total_event_interest

    totals = {k: sum(report[cat][k] for cat in categories) for k in report[categories[0]]}
    grand_total = sum(totals.values())

    return render_template('income_report.html',
                           report=report,
                           totals=totals,
                           grand_total=grand_total,
                           start_date=start_date.isoformat(),
                           end_date=end_date.isoformat(),
                           categories=categories)


# === Income computation helper ===
def _compute_income_db(start_date, end_date):
    start_dt = datetime.combine(start_date, datetime.min.time())
    end_dt = datetime.combine(end_date, datetime.max.time())

    # One-time income: fees at loan creation
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
        )
        .group_by(LoanApplication.category)
        .all()
    )
    print(f"One-time fees: {one_time}")


    # Scheduled income: interest and collection fees
    scheduled_income = (
        db.session.query(
            LoanApplication.category,
            func.coalesce(func.sum(RepaymentSchedule.expected_interest), 0).label('interest'),
            func.coalesce(func.sum(RepaymentSchedule.expected_fees), 0).label('collection')
        )
        .join(LoanApplication, LoanApplication.id == RepaymentSchedule.loan_id)
        .filter(
            RepaymentSchedule.due_date >= start_date,
            RepaymentSchedule.due_date <= end_date,
        )
        .group_by(LoanApplication.category)
        .all()
    )
    print(f"Scheduled income (interest/fees): {scheduled_income}")

    # Settlement and top-up interest (recognized at event month)
    event_interest = (
        db.session.query(
            LoanApplication.category,
            func.coalesce(func.sum(LoanApplication.settlement_interest), 0).label('settlement_interest'),
            func.coalesce(func.sum(LoanApplication.top_up_interest), 0).label('top_up_interest')
        )
        .filter(
            LoanApplication.closure_date != None,
            LoanApplication.closure_date >= start_dt,
            LoanApplication.closure_date < end_dt
        )
        .group_by(LoanApplication.category)
        .all()
    )
    print(f"Event-based interest: {event_interest}")

    return one_time, scheduled_income, event_interest


from flask import render_template, request
from datetime import datetime, timedelta, date
from sqlalchemy import func

@app.route('/detailed_income_breakdown', methods=['GET', 'POST'])
@login_required
@role_required('finance_officer', 'admin')
def detailed_income_breakdown():
    today = date.today()
    default_start = date(today.year, today.month, 1)
    default_end = date(today.year, today.month, calendar.monthrange(today.year, today.month)[1])

    if request.method == 'POST':
        start_date = _parse_date(request.form.get('start_date'), default_start)
        end_date = _parse_date(request.form.get('end_date'), default_end)
    else:
        start_date, end_date = default_start, default_end

    # Get loans with scheduled income (interest & collection fees)
    results = (
        db.session.query(
            LoanApplication.id.label('loan_id'),
            LoanApplication.loan_number,
            LoanApplication.category,
            LoanApplication.loan_amount,
            func.sum(RepaymentSchedule.expected_interest).label('expected_interest'),
            func.sum(RepaymentSchedule.expected_fees).label('expected_fees')
        )
        .join(RepaymentSchedule, RepaymentSchedule.loan_id == LoanApplication.id)
        .filter(
            RepaymentSchedule.due_date >= start_date,
            RepaymentSchedule.due_date <= end_date,
        )
        .group_by(
            LoanApplication.id,
            LoanApplication.loan_number,
            LoanApplication.category,
            LoanApplication.loan_amount
        )
        .having(
            or_(
                func.sum(RepaymentSchedule.expected_interest) > 0,
                func.sum(RepaymentSchedule.expected_fees) > 0
            )
        ))

    return render_template(
        'detailed_income_breakdown.html',
        results=results,
        start_date=start_date.isoformat(),
        end_date=end_date.isoformat()
    )


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

    value = value.strip()
    formats = ['%Y-%m-%d', '%m/%d/%Y', '%d-%m-%Y']

    for fmt in formats:
        try:
            return datetime.strptime(value, fmt)
        except ValueError:
            continue

    raise ValueError(f"Invalid date format for {field_name}. "
                     f"Use one of: {', '.join(formats)}")

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
                        # Remove old schedules
                        RepaymentSchedule.query.filter_by(loan_id=loan.id).delete()
                        db.session.flush()

                        # Only regenerate if loan has a positive amount
                        if loan.loan_amount > 0:
                            loan.generate_repayment_schedule(disbursement_date=loan.disbursement_date)
                                        
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

# utils/arrears.p
def refresh_all_arrears():
    print("Refreshing arrears...")
    db.session.query(Arrear).delete()  # Clear all previous arrears

    loans = LoanApplication.query.all()

    for loan in loans:
        overdue_schedules = [s for s in loan.repayment_schedule if s.due_date < date.today() and not s.fully_paid]

        for schedule in overdue_schedules:
            arrear = Arrear(
                loan_id=loan.id,
                schedule_id=schedule.id,
                due_date=schedule.due_date,
                recorded_at=date.today(),
                expected_principal=schedule.principal_due or 0,
                expected_interest=schedule.interest_due or 0,
                expected_fees=schedule.fees_due or 0,
                paid_principal=schedule.paid_principal or 0,
                paid_interest=schedule.paid_interest or 0,
                paid_fees=schedule.paid_fees or 0,
                payment_status='unpaid',
                status='unresolved',
                category=loan.category,
                tenure=loan.tenure
            )

            # Calculate aging
            age = (date.today() - arrear.due_date).days
            arrear.aging = age  # store on model

            if age <= 30:
                bracket = "1-30"
            elif age <= 60:
                bracket = "31-60"
            elif age <= 90:
                bracket = "61-90"
            elif age <= 180:
                bracket = "91-180"
            else:
                bracket = "180+"

            # Lookup provision rule
            rule = ProvisionSetting.query.filter_by(category=loan.category, tenure=loan.tenure).first()
            if rule:
                total_due = arrear.expected_principal + arrear.expected_interest + arrear.expected_fees
                provision = total_due * rule.probability_of_default * rule.loss_given_default
                arrear.probability_of_default = rule.probability_of_default
                arrear.loss_given_default = rule.loss_given_default
                arrear.provision_amount = round(provision, 2)

            db.session.add(arrear)

    db.session.commit()
    print("Arrears refreshed.")


@click.command("refresh-arrears")
@with_appcontext
def refresh_arrears():
    """Recalculate and update all arrears from repayment schedules."""
    refresh_all_arrears()

app.cli.add_command(refresh_arrears)

@app.route('/arrears')
@login_required
@role_required('admin', 'finance_officer')
def view_arrears():
    status = request.args.get('status', 'unresolved')
    aging = request.args.get('aging')
    tenure = request.args.get('tenure')
    category = request.args.get('category')

    query = Arrear.query.join(LoanApplication).join(Customer)

    if status:
        query = query.filter(Arrear.status == status)
    if aging:
        try:
            days = int(aging.split('-')[0])
            cutoff_date = datetime.utcnow().date() - timedelta(days=days)
            query = query.filter(Arrear.due_date <= cutoff_date)
        except:
            flash("Invalid aging filter", "danger")
    if tenure:
        query = query.filter(Arrear.tenure == int(tenure))
    if category:
        query = query.filter(LoanApplication.category == category)

    arrears = query.order_by(Arrear.due_date.asc()).all()

    # Distinct filters
    tenures = sorted(set([a.tenure for a in Arrear.query.distinct(Arrear.tenure).all() if a.tenure]))
    categories = sorted(set([la.category for la in LoanApplication.query.distinct(LoanApplication.category).all() if la.category]))

    # Tab 1: Aging Schedule
    aging_brackets = ['1-30', '31-60', '61-90', '91-180', '180+']
    aging_schedule = []

    for bracket in aging_brackets:
        loans = [a for a in arrears if get_bracket(a.days_past_due) == bracket]
        total_value = sum((a.expected_principal + a.expected_interest + a.expected_fees) for a in loans)
        total_prov = sum(a.provision_amount or 0 for a in loans)
        aging_schedule.append({
            'bracket': bracket.replace("-", " - "),
            'num_loans': len(loans),
            'value': total_value,
            'provision': total_prov
        })

    # Tab 2: Aging Summary
    total_arrears_value = sum((a.expected_principal + a.expected_interest + a.expected_fees) for a in arrears)
    aging_summary = []
    for row in aging_schedule:
        percentage = (row['value'] / total_arrears_value) * 100 if total_arrears_value else 0
        aging_summary.append({
            'bracket': row['bracket'],
            'amount': row['value'],
            'percentage': percentage
        })

    return render_template(
        'portfolio/arrears_report.html',
        arrears=arrears,
        status=status,
        aging=aging,
        tenure=tenure,
        category=category,
        tenures=tenures,
        categories=categories,
        aging_schedule=aging_schedule,
        aging_summary=aging_summary
    )

def get_bracket(age):
    if age <= 30:
        return "1-30"
    elif age <= 60:
        return "31-60"
    elif age <= 90:
        return "61-90"
    elif age <= 180:
        return "91-180"
    return "180+"



@app.route('/resolve_arrear/<int:arrear_id>', methods=['POST'])
@login_required
@role_required('admin', 'finance_officer')
def resolve_arrear(arrear_id):
    arrear = Arrear.query.get_or_404(arrear_id)
    resolution_type = request.form.get('resolution_type')
    notes = request.form.get('notes', '')

    if resolution_type == 'waiver':
        journal = JournalEntry(
            description=f"Arrear waiver for loan {arrear.loan.loan_number}",
            amount=arrear.total_arrears,
            entry_type='waiver',
            gl_account='income_waiver',
            user_id=current_user.id,
            loan_id=arrear.loan_id
        )
        db.session.add(journal)

    arrear.status = 'resolved'
    arrear.resolution_type = resolution_type
    arrear.resolution_notes = notes
    arrear.resolved_by = current_user.id
    arrear.resolution_date = datetime.utcnow()

    db.session.commit()
    flash('Arrear resolved successfully', 'success')
    return redirect(url_for('arrears_waterfall'))

def create_notification(message, recipient_id=None, type='info'):
    note = Notification(
        message=message,
        recipient_id=recipient_id,
        type=type,
        is_read=False
    )
    db.session.add(note)
    db.session.commit()

def alert_on_new_arrear(arrear):
    # Fetch users to notify — e.g., credit officers role users
    credit_officers = User.query.filter(User.role == 'credit_officer').all()
    for officer in credit_officers:
        create_notification(
            message=f"New arrear recorded on Loan #{arrear.loan_id} with due date {arrear.due_date}.",
            recipient_id=officer.id,
            type='warning'
        )



@app.route('/dashboard/credit_officer')
@login_required
@role_required('credit_officer', 'admin')
def credit_officer_dashboard():
    # Get unread notifications for current user
    unread_notifications = Notification.query.filter_by(
        recipient_id=current_user.id,
        is_read=False
    ).order_by(Notification.timestamp.desc()).all()

    # Define tasks with their display names and URLs (adjust URLs as needed)
    tasks = [
        
        {'name': 'Approve Loans', 'url': url_for('approve_loans')},
        {'name': 'View Arrears', 'url': url_for('view_arrears')},
        # add other tasks here...
    ]

    return render_template('dashboard/credit_officer.html',
                           unread_notifications=unread_notifications,
                           tasks=tasks)


@app.route('/provision-rule', methods=['POST'])
@login_required
def save_provision_rule():
    category = request.form['category']
    tenure_group = request.form['tenure_group']
    if '+' in tenure_group:
        tenure = int(tenure_group.replace('+', ''))
    else:
        tenure = int(tenure_group.split('-')[0])

  # or parse tenure_group appropriately
    pd = float(request.form['pd'])
    lgd = float(request.form['lgd'])

    rule = ProvisionSetting.query.filter_by(category=category, tenure=tenure).first()
    if rule:
        rule.probability_of_default = pd
        rule.loss_given_default = lgd
    else:
        rule = ProvisionSetting(category=category, tenure=tenure, probability_of_default=pd, loss_given_default=lgd)
        db.session.add(rule)

    db.session.commit()
    flash(f'Provision rule saved for {category} [{tenure}]', 'success')
    return redirect(url_for('view_arrears'))

def calculate_par(loans, threshold):
    total = sum(loan.balance for loan in loans)
    overdue = sum(loan.balance for loan in loans if loan.days_past_due >= threshold)
    return round((overdue / total) * 100, 2) if total > 0 else 0.0

def snapshot_par():
    with app.app_context():
        loans = LoanApplication.query.all()
        snapshot_date = date.today()
        if PARSnapshot.query.filter_by(snapshot_date=snapshot_date).first():
            return
        par_30 = calculate_par(loans, 30)
        par_60 = calculate_par(loans, 60)
        par_90 = calculate_par(loans, 90)
        snapshot = PARSnapshot(snapshot_date=snapshot_date, par_30=par_30, par_60=par_60, par_90=par_90)
        db.session.add(snapshot)
        db.session.commit()

scheduler = BackgroundScheduler()
scheduler.add_job(snapshot_par, 'cron', day_of_week='sun', hour=0, minute=0)
scheduler.start()


from flask import request, render_template, make_response
from datetime import datetime, timedelta
import csv, io

def get_par_data_for_period(period_key, category=None, tenure=None):
    today = datetime.today()

    if period_key == 'this_quarter':
        start = today - timedelta(weeks=12)
        factor = 1.0
    elif period_key == 'last_quarter':
        start = today - timedelta(weeks=24)
        factor = 0.8
    elif period_key == 'same_quarter_last_year':
        start = today - timedelta(weeks=56)
        factor = 1.3
    elif period_key == '12w':
        start = today - timedelta(weeks=12)
        factor = 0.9
    else:
        start = today - timedelta(weeks=12)
        factor = 1.0

    weeks = list(range(12))
    dates = [(start + timedelta(weeks=i)).strftime('%Y-%m-%d') for i in weeks]

    # Simulated PAR % values
    par30_percent = [round(factor * (5 + i * 0.4), 2) for i in weeks]
    par60_percent = [round(factor * (3 + i * 0.25), 2) for i in weeks]
    par90_percent = [round(factor * (1 + i * 0.15), 2) for i in weeks]

    # Compute MWK amounts from % of total portfolio
    base_portfolio_amount = 100000  # In MWK
    par30_amount = [round(base_portfolio_amount * p / 100) for p in par30_percent]
    par60_amount = [round(base_portfolio_amount * p / 100) for p in par60_percent]
    par90_amount = [round(base_portfolio_amount * p / 100) for p in par90_percent]

    return dates, weeks, {
        'par30': {'percent': par30_percent, 'amount': par30_amount},
        'par60': {'percent': par60_percent, 'amount': par60_amount},
        'par90': {'percent': par90_percent, 'amount': par90_amount},
    }


@app.route('/par-trend', methods=['GET'])
def par_trend():
    # Get query parameters
    period1 = request.args.get('period1', '12w')
    period2 = request.args.get('period2', 'last_quarter')
    category = request.args.get('category')
    tenure = request.args.get('tenure')
    par_filter = int(request.args.get('par', 30))  # 30, 60, or 90

    # Get structured data for both periods
    dates1, weeks1, data1 = get_par_data_for_period(period1, category, tenure)
    dates2, weeks2, data2 = get_par_data_for_period(period2, category, tenure)

    # Extract relevant PAR level data
    key = f'par{par_filter}'
    par_percent1 = data1[key]['percent']
    par_amount1 = data1[key]['amount']
    par_percent2 = data2[key]['percent']
    par_amount2 = data2[key]['amount']

    # Combine data for display or chart
    zipped1 = list(zip(dates1, par_amount1, par_percent1))
    zipped2 = list(zip(dates2, par_amount2, par_percent2))

    return render_template(
        'par_trend.html',
        period1=period1,
        period2=period2,
        category=category,
        tenure=tenure,
        par=par_filter,
        week_labels=dates1,
        par_amount1=par_amount1,
        par_percent1=par_percent1,
        par_amount2=par_amount2,
        par_percent2=par_percent2,
        zipped1=zipped1,
        zipped2=zipped2
    )



@app.route('/par-trend/download', methods=['GET'])
def download_par_csv():
    period1 = request.args.get('period1', 'this_quarter')
    period2 = request.args.get('period2', 'last_quarter')
    category = request.args.get('category')
    tenure = request.args.get('tenure')
    par_bucket = request.args.get('par_bucket', 'all')

    dates1, weeks1, data1 = get_par_data_for_period(period1, category, tenure)
    dates2, weeks2, data2 = get_par_data_for_period(period2, category, tenure)

    if par_bucket in ['par30', 'par60', 'par90']:
        parPercent_1 = data1[par_bucket]['percent']
        parPercent_2 = data2[par_bucket]['percent']
        parAmount_1 = data1[par_bucket]['amount']
        parAmount_2 = data2[par_bucket]['amount']
    else:
        parPercent_1 = [round((data1['par30']['percent'][i] + data1['par60']['percent'][i] + data1['par90']['percent'][i]) / 3, 2) for i in range(12)]
        parPercent_2 = [round((data2['par30']['percent'][i] + data2['par60']['percent'][i] + data2['par90']['percent'][i]) / 3, 2) for i in range(12)]
        parAmount_1 = [data1['par30']['amount'][i] + data1['par60']['amount'][i] + data1['par90']['amount'][i] for i in range(12)]
        parAmount_2 = [data2['par30']['amount'][i] + data2['par60']['amount'][i] + data2['par90']['amount'][i] for i in range(12)]

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        'Date (Period 1)', 'PAR % (P1)', 'PAR Amount (P1)',
        'Date (Period 2)', 'PAR % (P2)', 'PAR Amount (P2)'
    ])

    max_len = max(len(dates1), len(dates2))
    for i in range(max_len):
        row = []
        row.extend([dates1[i], parPercent_1[i], parAmount_1[i]] if i < len(dates1) else ['', '', ''])
        row.extend([dates2[i], parPercent_2[i], parAmount_2[i]] if i < len(dates2) else ['', '', ''])
        writer.writerow(row)

    output.seek(0)
    response = make_response(output.getvalue())
    response.headers["Content-Disposition"] = f"attachment; filename=par_trend_{period1}_vs_{period2}.csv"
    response.headers["Content-type"] = "text/csv"
    return response

def get_arrears_data(period_key, category=None, tenure=None):
    today = datetime.today()

    if period_key == 'this_quarter':
        start = today - timedelta(weeks=12)
        offset = 0
    elif period_key == 'last_quarter':
        start = today - timedelta(weeks=24)
        offset = 20
    elif period_key == 'same_quarter_last_year':
        start = today - timedelta(weeks=56)
        offset = -15
    else:
        start = today - timedelta(weeks=12)
        offset = 10

    weeks = [f'WK{i+1}' for i in range(12)]  # Create week labels
    dates = [(start + timedelta(weeks=i)).strftime('%Y-%m-%d') for i in range(12)]
    count = [int(40 + offset + i * 1.5 + (10 if category else 0)) for i in range(12)]
    amount = [round(8000 + offset * 50 + i * 600 + (100 * int(tenure) if tenure else 0), 2) for i in range(12)]

    return dates, weeks, count, amount


@app.route('/arrears-trend', methods=['GET'])
def arrears_trend():
    p1 = request.args.get('period1', '12w')
    p2 = request.args.get('period2', 'last_quarter')
    cat = request.args.get('category')
    ten = request.args.get('tenure')

    dates1, weeks1, count1, amount1 = get_arrears_data(p1, cat, ten)
    dates2, weeks2, count2, amount2 = get_arrears_data(p2, cat, ten)

    return render_template(
        'portfolio/arrears_trend.html',
        period1=p1,
        period2=p2,
        category=cat,
        tenure=ten,
        week_labels=weeks1,
        count1=count1,
        amount1=amount1,
        count2=count2,
        amount2=amount2,
        zipped1=zip(dates1, count1, amount1),
        zipped2=zip(dates2, count2, amount2)
    )


@app.route('/arrears-trend/download')
def download_arrears_csv():
    period1 = request.args.get('period1', 'this_quarter')
    period2 = request.args.get('period2', 'last_quarter')
    category = request.args.get('category')
    tenure = request.args.get('tenure')

    dates1, count1, amount1 = get_arrears_data(period1, category, tenure)
    dates2, count2, amount2 = get_arrears_data(period2, category, tenure)

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        'Date (Period 1)', 'Count (P1)', 'Amount (P1)',
        'Date (Period 2)', 'Count (P2)', 'Amount (P2)'
    ])

    max_len = max(len(dates1), len(dates2))
    for i in range(max_len):
        row = [
            dates1[i] if i < len(dates1) else '',
            count1[i] if i < len(count1) else '',
            amount1[i] if i < len(amount1) else '',
            dates2[i] if i < len(dates2) else '',
            count2[i] if i < len(count2) else '',
            amount2[i] if i < len(amount2) else ''
        ]
        writer.writerow(row)

    output.seek(0)
    response = make_response(output.getvalue())
    response.headers["Content-Disposition"] = f"attachment; filename=arrears_trend_{period1}_vs_{period2}.csv"
    response.headers["Content-type"] = "text/csv"
    return response

from collections import defaultdict
from datetime import datetime, timedelta
from flask import request, render_template, redirect, url_for, flash
from flask_login import current_user, login_required

CATEGORY_MAP = {
    1: 'civil_servant',
    2: 'private_sector',
    3: 'sme'
}

@app.route('/arrears-waterfall', methods=['GET', 'POST'])
@role_required('credit_officer', 'admin')
def arrears_waterfall():
    status = request.args.get('status', 'unresolved')
    tenure = request.args.get('tenure')
    category = request.args.get('category')
    
    # POST: update reason/action for arrears
    if request.method == 'POST':
        for key, value in request.form.items():
            if key.startswith('reason_') or key.startswith('action_'):
                field, arrear_id = key.split('_')
                arrear = Arrear.query.get(int(arrear_id))
                if arrear:
                    if field == 'reason':
                        arrear.arrear_reason = value.strip()
                    elif field == 'action':
                        arrear.action_plan = value.strip()
        db.session.commit()
        flash("Arrears updated.", "success")
        return redirect(url_for('arrears_waterfall', **request.args))

    arrears_query = Arrear.query.join(LoanApplication)
    
    if status == 'resolved':
        arrears_query = arrears_query.filter(Arrear.status == 'resolved')
    else:
        arrears_query = arrears_query.filter(Arrear.status != 'resolved')

    # Filter by tenure
    if tenure:
        arrears_query = arrears_query.filter(Arrear.tenure == int(tenure))

    # Filter by category
    if category:
        arrears_query = arrears_query.filter(LoanApplication.category == category)

    arrears = arrears_query.order_by(Arrear.due_date.desc()).all()

    # Prepare summary data for waterfall chart by arrear_reason
    summary = defaultdict(lambda: {'count': 0, 'amount': 0.0})
    for a in arrears:
        reason = a.arrear_reason or 'Unspecified'
        summary[reason]['count'] += 1
        summary[reason]['amount'] += a.total_arrears or 0.0

    # Sort by count descending
    sorted_summary = sorted(summary.items(), key=lambda x: x[1]['count'], reverse=True)
    
    labels = [item[0] for item in sorted_summary]
    counts = [item[1]['count'] for item in sorted_summary]
    amounts = [round(item[1]['amount'], 2) for item in sorted_summary]

    summary_data = {
        'labels': labels,
        'counts': counts,
        'amounts': amounts
    }

    # Get distinct values for filters
    tenures = sorted({a.tenure for a in Arrear.query.with_entities(Arrear.tenure).distinct() if a.tenure})
    categories = list({app.category for app in LoanApplication.query.with_entities(LoanApplication.category).distinct()})

    return render_template('portfolio/arrears_waterfall.html',
                           arrears=arrears,
                           status=status,
                           tenure=tenure,
                           category=category,
                           tenures=tenures,
                           categories=categories,
                           summary_data=summary_data)


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


def generate_placement_schedule(placement):
    from datetime import datetime
    from dateutil.relativedelta import relativedelta

    start_date = placement.start_date
    tenure = placement.tenure_months or 0
    frequency = placement.payment_frequency_months or 1  # fallback default
    rate_annual = (placement.interest_rate or 0) / 100
    principal = placement.amount or 0.0

    # Validate inputs
    if frequency <= 0 or tenure <= 0 or principal <= 0:
        return []

    num_periods = tenure // frequency
    if num_periods <= 0:
        return []

    periodic_rate = rate_annual * (frequency / 12)
    schedule = []

    # Compound Interest (Amortized)
    if placement.interest_type == 'Compound':
        if periodic_rate > 0:
            emi = principal * (periodic_rate * (1 + periodic_rate) ** num_periods) / ((1 + periodic_rate) ** num_periods - 1)
        else:
            emi = principal / num_periods

        emi = round(emi, 2)
        balance = principal

        for i in range(num_periods):
            due_date = start_date + relativedelta(months=frequency * (i + 1))
            interest_due = round(balance * periodic_rate, 2)
            principal_due = round(emi - interest_due, 2)
            balance = round(balance - principal_due, 2)

            if i == num_periods - 1:
                principal_due += balance
                interest_due = round(emi - principal_due, 2)
                balance = 0.0

            schedule.append(PlacementSchedule(
                placement_id=placement.id,
                due_date=due_date,
                interest_due=interest_due,
                principal_due=principal_due,
                total_due=round(interest_due + principal_due, 2),
                is_paid=False
            ))

    # Simple Interest
    elif placement.interest_type == 'Simple':
        total_interest = principal * rate_annual * (tenure / 12)
        interest_per_period = round(total_interest / num_periods, 2)

        for i in range(num_periods):
            due_date = start_date + relativedelta(months=frequency * (i + 1))
            schedule.append(PlacementSchedule(
                placement_id=placement.id,
                due_date=due_date,
                interest_due=interest_per_period,
                principal_due=0.0,
                total_due=interest_per_period,
                is_paid=False
            ))

    return schedule

@app.route('/placement/new', methods=['GET', 'POST'])
def new_placement():
    form = PlacementForm()
    form.client_id.choices = [(c.id, c.full_name) for c in Client.query.all()]

    if form.validate_on_submit():
        placement_number = generate_placement_number(form.tenure_months.data)

        # Set a safe default for payment frequency
        payment_freq = form.payment_frequency_months.data or 1

        placement = Placement(
            client_id=form.client_id.data,
            amount=form.amount.data,
            interest_rate=form.interest_rate.data,
            interest_type=form.interest_type.data,
            tenure_months=form.tenure_months.data,
            start_date=form.start_date.data,
            payment_frequency_months=payment_freq,
            commission_percentage=form.commission_percentage.data,
            arrangement_fee=form.arrangement_fee.data,
            collateral=form.collateral.data,
            due_date=form.start_date.data + relativedelta(months=form.tenure_months.data),
            current_balance=form.amount.data,
            placement_number=placement_number,
            interest_due=0.0,
            principal_due=0.0,
            total_due=0.0,
            is_paid=False,
            status="Active",
            last_interest_calculation=form.start_date.data
        )
        db.session.add(placement)
        db.session.commit()

        # Generate repayment schedule
        schedule = generate_placement_schedule(placement)
        if schedule:
            db.session.bulk_save_objects(schedule)

        # Create initial deposit transaction
        transaction = PlacementTransaction(
            placement_id=placement.id,
            transaction_type='Deposit',
            amount=form.amount.data,
            description='Initial deposit'
        )
        db.session.add(transaction)
        db.session.commit()

        flash("Placement created successfully", "success")
        return redirect(url_for('placement_details', placement_id=placement.id))

    return render_template('placement/new.html', form=form)



@app.route('/placement/<int:placement_id>')
def placement_details(placement_id):
    placement = Placement.query.get_or_404(placement_id)
    transactions = PlacementTransaction.query.filter_by(placement_id=placement_id)\
        .order_by(PlacementTransaction.transaction_date.desc()).all()
    accrued_interest = placement.accrued_interest()
    
    return render_template('placement/details.html', 
                          placement=placement,
                          transactions=transactions,
                          accrued_interest=accrued_interest)

@app.route('/placement/<int:placement_id>/deposit', methods=['GET', 'POST'])
def add_deposit(placement_id):
    placement = Placement.query.get_or_404(placement_id)
    form = DepositForm()
    
    if form.validate_on_submit():
        try:
            placement.add_deposit(form.amount.data, form.transaction_date.data)
            db.session.commit()
            flash("Deposit added successfully", "success")
            return redirect(url_for('placement_details', placement_id=placement.id))
        except Exception as e:
            flash(str(e), "danger")
    
    return render_template('placement/deposit.html', form=form, placement=placement)

@app.route('/placement/<int:placement_id>/withdraw', methods=['GET', 'POST'])
def withdraw_funds(placement_id):
    placement = Placement.query.get_or_404(placement_id)
    form = WithdrawalForm()
    
    if form.validate_on_submit():
        try:
            placement.withdraw_funds(form.amount.data, form.transaction_date.data)
            db.session.commit()
            flash("Withdrawal processed successfully", "success")
            return redirect(url_for('placement_details', placement_id=placement.id))
        except Exception as e:
            flash(str(e), "danger")
    
    return render_template('placement/withdraw.html', form=form, placement=placement)

@app.route('/placement/<int:placement_id>/change_rate', methods=['GET', 'POST'])
def change_interest_rate(placement_id):
    placement = Placement.query.get_or_404(placement_id)
    form = RateChangeForm()
    
    if form.validate_on_submit():
        placement.change_interest_rate(form.new_rate.data, form.effective_date.data)
        db.session.commit()
        flash("Interest rate changed successfully", "success")
        return redirect(url_for('placement_details', placement_id=placement_id))
    
    return render_template('placement/change_rate.html', form=form, placement=placement)

@app.route('/placement/<int:placement_id>/capitalize', methods=['GET', 'POST'])
def capitalize_interest(placement_id):
    placement = Placement.query.get_or_404(placement_id)
    form = CapitalizeForm()
    
    if form.validate_on_submit():
        interest = placement.capitalize_interest(form.transaction_date.data)
        if interest > 0:
            db.session.commit()
            flash(f"${interest:,.2f} interest capitalized", "success")
        else:
            flash("No interest to capitalize", "info")
        return redirect(url_for('placement_details', placement_id=placement_id))
    
    return render_template('placement/capitalize.html', form=form, placement=placement)

@app.route('/placement/<int:placement_id>/liquidate', methods=['GET', 'POST'])
def liquidate_placement(placement_id):
    placement = Placement.query.get_or_404(placement_id)
    form = LiquidateForm()
    
    if form.validate_on_submit():
        final_balance = placement.liquidate(form.transaction_date.data)
        db.session.commit()
        flash(f"Placement liquidated. Final balance: ${final_balance:,.2f}", "success")
        return redirect(url_for('placement_details', placement_id=placement_id))
    
    return render_template('placement/liquidate.html', form=form, placement=placement)

@app.route('/placements')
def view_placements():
    from datetime import date

    today = date.today()
    month_start = today.replace(day=1)
    if today.month == 12:
        month_end = today.replace(year=today.year + 1, month=1, day=1)
    else:
        month_end = today.replace(month=today.month + 1, day=1)

    placements_query = Placement.query

    interest_start = request.args.get('interest_start')
    interest_end = request.args.get('interest_end')
    maturity_start = request.args.get('maturity_start')
    maturity_end = request.args.get('maturity_end')

    if interest_start:
        placements_query = placements_query.filter(Placement.next_interest_date >= interest_start)
    if interest_end:
        placements_query = placements_query.filter(Placement.next_interest_date <= interest_end)
    if maturity_start:
        placements_query = placements_query.filter(Placement.start_date >= maturity_start)
    if maturity_end:
        placements_query = placements_query.filter(Placement.maturity_date <= maturity_end)

    placements = placements_query.all()

    # Get scheduled interest per placement this month
    scheduled_map = {
        row.placement_id: row.interest_due
        for row in db.session.query(
            PlacementSchedule.placement_id,
            db.func.sum(PlacementSchedule.interest_due).label('interest_due')
        ).filter(
            PlacementSchedule.due_date >= month_start,
            PlacementSchedule.due_date < month_end
        ).group_by(PlacementSchedule.placement_id).all()
    }

    total_amount = 0
    weighted_cost_sum = 0
    total_interest = 0
    total_scheduled_interest = 0
    total_balance = 0

    for p in placements:
        p.scheduled_interest = scheduled_map.get(p.id, 0.0)
        p.total_cost = (p.interest_rate or 0) + (p.commission_percentage or 0) + (p.arrangement_fee or 0)

        total_interest += p.accrued_interest() or 0
        total_scheduled_interest += p.scheduled_interest
        total_balance += p.current_balance or 0
        total_amount += p.amount or 0
        weighted_cost_sum += (p.amount or 0) * p.total_cost

    weighted_cost = (weighted_cost_sum / total_amount) if total_amount else 0.0

    return render_template(
        'placement/list.html',
        placements=placements,
        total_interest=total_interest,
        total_scheduled_interest=total_scheduled_interest,
        total_balance=total_balance,
        weighted_cost=weighted_cost
    )


@app.route('/placements/export')
def export_placements_excel():
    import pandas as pd
    from io import BytesIO
    from flask import send_file

    placements = Placement.query.all()

    data = [{
        'Client': p.client.full_name if p.client else 'N/A',
        'Start Date': p.start_date,
        'Maturity Date': p.maturity_date,
        'Interest Rate': p.interest_rate,
        'Commission %': p.commission_percentage,
        'Arrangement Fee %': p.arrangement_fee,
        'Total Cost %': (p.interest_rate or 0) + (p.commission_percentage or 0) + (p.arrangement_fee or 0),
        'Balance': p.current_balance,
        'Status': p.status,
    } for p in placements]

    df = pd.DataFrame(data)
    output = BytesIO()
    df.to_excel(output, index=False)
    output.seek(0)

    return send_file(output, mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
                     download_name='placements.xlsx', as_attachment=True)


from datetime import date
from collections import defaultdict
from datetime import date

def get_scheduled_interest_by_placement():
    today = date.today()
    month_start = today.replace(day=1)
    if today.month == 12:
        month_end = today.replace(year=today.year + 1, month=1, day=1)
    else:
        month_end = today.replace(month=today.month + 1, day=1)

    results = db.session.query(
        PlacementSchedule.placement_id,
        db.func.sum(PlacementSchedule.interest_due)
    ).filter(
        PlacementSchedule.due_date >= month_start,
        PlacementSchedule.due_date < month_end
    ).group_by(PlacementSchedule.placement_id).all()

    return {pid: total for pid, total in results}


def get_monthly_scheduled_interest():
    today = date.today()
    month_start = today.replace(day=1)
    if today.month == 12:
        month_end = today.replace(year=today.year + 1, month=1, day=1)
    else:
        month_end = today.replace(month=today.month + 1, day=1)

    return db.session.query(
        db.func.sum(PlacementSchedule.interest_due)
    ).filter(
        PlacementSchedule.due_date >= month_start,
        PlacementSchedule.due_date < month_end
    ).scalar() or 0.0

@app.route('/placements-interest')
def placements_interest():
    total_interest = get_monthly_scheduled_interest()
    placements = Placement.query.all()

    # Optionally, attach scheduled interest per placement if needed:
    # This requires a query per placement or a batch query to be efficient,
    # but if you want just the total scheduled interest overall, this is enough.

    return render_template('placement/list.html', placements=placements, total_interest=total_interest)


# Add Jinja currency filter
@app.template_filter('format_currency')
def format_currency_filter(value):
    try:
        return "${:,.2f}".format(value or 0)
    except Exception:
        return "$0.00"


from sqlalchemy import func

def generate_placement_number(tenure_months):
    now = datetime.utcnow()
    month = now.strftime('%m')
    year = now.strftime('%y')

    # Get the last sequence number
    last_placement = Placement.query.order_by(Placement.id.desc()).first()
    last_seq = 0
    if last_placement and last_placement.placement_number:
        try:
            last_seq = int(last_placement.placement_number[-4:])
        except:
            pass
    next_seq = last_seq + 1
    return f"{int(tenure_months):02d}{month}{year}{next_seq:04d}"


@app.route('/placement/<int:placement_id>/statement')
def placement_statement(placement_id):
    placement = Placement.query.get_or_404(placement_id)
    transactions = PlacementTransaction.query.filter_by(placement_id=placement_id)\
        .order_by(PlacementTransaction.transaction_date.asc()).all()

    return render_template('placement/statement.html',
                           placement=placement,
                           transactions=transactions)

from dateutil.relativedelta import relativedelta


def calculate_interest_due(placement, period_index, total_periods):
    """You can customize interest calculation per frequency."""
    # Simple example: evenly divide total interest
    total_interest = placement.amount * (placement.interest_rate / 100) * (placement.tenure_months / 12)
    return round(total_interest / total_periods, 2)

@app.route('/placement/<int:placement_id>/schedule')
def view_placement_schedule(placement_id):
    placement = Placement.query.get_or_404(placement_id)
    schedule = PlacementSchedule.query.filter_by(placement_id=placement_id).order_by(PlacementSchedule.due_date).all()
    return render_template('placement/schedule.html', placement=placement, schedule=schedule)

@app.route('/add-client', methods=['GET', 'POST'])
def add_client():
    form = ClientForm()
    if form.validate_on_submit():
        existing = Client.query.filter_by(national_id=form.national_id.data).first()
        if existing:
            flash('Client already exists', 'warning')
        else:
            new_client = Client(
                full_name=form.full_name.data,
                national_id=form.national_id.data,
                phone=form.phone.data,
                email=form.email.data
            )
            db.session.add(new_client)
            db.session.commit()
            flash('Client added successfully', 'success')
            return redirect(url_for('add_client'))

    return render_template('add_client.html', form=form)


def change_tenure(self, new_tenure, effective_date):
    from dateutil.relativedelta import relativedelta

    # Capitalize interest up to effective_date
    self.capitalize_interest(effective_date)

    # Update tenure and due_date
    self.tenure_months = new_tenure
    self.due_date = self.start_date + relativedelta(months=new_tenure)
    self.last_interest_calculation = effective_date

    # Delete old schedules
    PlacementSchedule.query.filter_by(placement_id=self.id).delete()

    # Generate new schedule
    new_schedule = generate_placement_schedule(self)
    if new_schedule:
        db.session.bulk_save_objects(new_schedule)

    db.session.commit()

def update_frequency(self, new_frequency, effective_date):
    from dateutil.relativedelta import relativedelta

    # Capitalize interest up to effective_date
    self.capitalize_interest(effective_date)

    # Update frequency
    freq_map = {
        'monthly': 1,
        'quarterly': 3,
        'annually': 12
    }
    self.payment_frequency_months = freq_map.get(new_frequency, 1)
    self.payment_frequency = new_frequency.capitalize()
    self.last_interest_calculation = effective_date

    # Delete old schedules
    PlacementSchedule.query.filter_by(placement_id=self.id).delete()

    # Generate new schedule
    new_schedule = generate_placement_schedule(self)
    if new_schedule:
        db.session.bulk_save_objects(new_schedule)

    db.session.commit()



@app.route("/placement/<int:placement_id>/update", methods=["GET", "POST"])
def update_placement(placement_id):
    placement = Placement.query.get_or_404(placement_id)
    form = PlacementUpdateForm()

    if form.validate_on_submit():
        changes_made = False
        effective_date = form.effective_date.data
        description = form.description.data or "Placement update"

        # Handle deposit or withdrawal
        if form.amount.data:
            amount = float(form.amount.data)
            if amount > 0:
                placement.amount += amount
                placement.current_balance += amount
                tx = PlacementTransaction(
                    placement_id=placement.id,
                    transaction_type='Deposit',
                    amount=amount,
                    description=description,
                    transaction_date=effective_date
                )
                db.session.add(tx)
            elif amount < 0:
                withdrawal_amount = abs(amount)
                if withdrawal_amount > placement.current_balance:
                    flash("Insufficient balance for withdrawal", "danger")
                    return redirect(request.url)
                placement.amount -= withdrawal_amount
                placement.current_balance -= withdrawal_amount
                tx = PlacementTransaction(
                    placement_id=placement.id,
                    transaction_type='Withdrawal',
                    amount=withdrawal_amount,
                    description=description,
                    transaction_date=effective_date
                )
                db.session.add(tx)
            changes_made = True

        # Handle interest rate change
        if form.new_interest_rate.data is not None:
            placement.interest_rate = float(form.new_interest_rate.data)
            tx = PlacementTransaction(
                placement_id=placement.id,
                transaction_type='Interest Rate Change',
                amount=0.0,
                description=f"Rate changed to {form.new_interest_rate.data}%",
                transaction_date=effective_date
            )
            db.session.add(tx)
            changes_made = True

        # Handle tenure change
        if form.new_tenure_months.data is not None:
            placement.tenure_months = form.new_tenure_months.data
            tx = PlacementTransaction(
                placement_id=placement.id,
                transaction_type='Tenure Change',
                amount=0.0,
                description=f"Tenure changed to {form.new_tenure_months.data} months",
                transaction_date=effective_date
            )
            db.session.add(tx)
            changes_made = True

        # Handle frequency change
        if form.new_payment_frequency.data is not None:
            placement.payment_frequency_months = form.new_payment_frequency.data
            tx = PlacementTransaction(
                placement_id=placement.id,
                transaction_type='Frequency Change',
                amount=0.0,
                description=f"Frequency changed to {form.new_payment_frequency.data} months",
                transaction_date=effective_date
            )
            db.session.add(tx)
            changes_made = True

        if changes_made:
            # Recalculate due date
            placement.due_date = placement.start_date + relativedelta(months=placement.tenure_months)

            # Delete old schedule and regenerate
            PlacementSchedule.query.filter_by(placement_id=placement.id).delete()
            new_schedule = generate_placement_schedule(placement)
            db.session.bulk_save_objects(new_schedule)

            db.session.commit()
            flash("Placement updated and schedule regenerated.", "success")
            return redirect(url_for('placement_details', placement_id=placement.id))
        else:
            flash("No changes submitted.", "warning")

    # Pre-fill form with current values
    if request.method == 'GET':
        form.new_interest_rate.data = placement.interest_rate
        form.new_tenure_months.data = placement.tenure_months
        form.new_payment_frequency.data = placement.payment_frequency_months
        form.effective_date.data = date.today()

    return render_template("placement/update.html", form=form, placement=placement)


from flask import render_template, request, redirect, url_for, flash, jsonify
from datetime import datetime, timedelta, date
from sqlalchemy import func, distinct, cast, Date
from app import app, db, mail
from flask_mail import Message
from apscheduler.schedulers.background import BackgroundScheduler
import calendar

from sqlalchemy import func, cast, Date, distinct, and_

from datetime import date, datetime

def get_agent_loan_stats(start: date, end: date, region=None, district=None, team_leader=None):
    start_dt = datetime.combine(start, datetime.min.time())
    end_dt = datetime.combine(end, datetime.max.time())

    query = (
        db.session.query(
            Agent.id.label("agent_id"),
            Agent.name.label("agent_name"),
            Agent.region,
            Agent.district,
            Agent.monthly_budget,
            Agent.team_leader_id,
            func.count(LoanApplication.id).label("applications"),
            func.coalesce(func.sum(LoanApplication.loan_amount), 0).label("total_loan_amount"),
            func.count(distinct(cast(LoanApplication.created_at, Date))).label("active_days")
        )
        .join(LoanApplication, LoanApplication.agent_id == Agent.id)
        .filter(Agent.active.is_(True), Agent.role != 'Team Leader')
        .filter(LoanApplication.created_at >= start_dt, LoanApplication.created_at <= end_dt)
    )

    if region:
        query = query.filter(Agent.region == region)
    if district:
        query = query.filter(Agent.district == district)
    if team_leader:
        query = query.filter(Agent.team_leader_id == int(team_leader))

    query = query.group_by(Agent.id).order_by(Agent.name)
    return query.all()

@app.route('/dashboard/sales')
def sales_dashboard():
    region = request.args.get('region')
    district = request.args.get('district')
    team_leader = request.args.get('team_leader')
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')

    today = date.today()
    start = datetime.strptime(start_date, "%Y-%m-%d").date() if start_date else today.replace(day=1)
    end = datetime.strptime(end_date, "%Y-%m-%d").date() if end_date else today

    agent_stats = get_agent_loan_stats(start, end, region, district, team_leader)

    # Prepare stats for template
    stats = []
    for row in agent_stats:
        applications_per_day = round(row.applications / row.active_days, 2) if row.active_days else 0
        budget_achievement = round((row.total_loan_amount / row.monthly_budget) * 100, 1) if row.monthly_budget else None
        stats.append({
            'name': row.agent_name,
            'region': row.region,
            'district': row.district,
            'applications': row.applications,
            'applications_per_day': applications_per_day,
            'active_days': row.active_days,
            'total_loan_amount': row.total_loan_amount,
            'budget': row.monthly_budget,
            'budget_achievement': budget_achievement
        })

    # Dropdown sources
    regions = [r[0] for r in db.session.query(Agent.region)
               .filter(Agent.role != 'Team Leader')
               .distinct().order_by(Agent.region)]
    districts = [d[0] for d in db.session.query(Agent.district)
                 .filter(Agent.role != 'Team Leader')
                 .distinct().order_by(Agent.district)]
    team_leads = db.session.query(Agent.id, Agent.name) \
        .filter(Agent.role == 'Team Leader').order_by(Agent.name).all()

    notif = get_sales_notification()

    return render_template(
        "dashboard/sales_dashboard.html",
        stats=stats,
        regions=regions,
        districts=districts,
        team_leads=team_leads,
        active_tab="agent",
        notif=notif
    )


from sqlalchemy.orm import aliased
from sqlalchemy import func, and_, distinct
from datetime import datetime, date, time

@app.route('/dashboard/team-leader')
def team_leader_dashboard():
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')

    today = date.today()
    start = datetime.strptime(start_date, "%Y-%m-%d").date() if start_date else today.replace(day=1)
    end = datetime.strptime(end_date, "%Y-%m-%d").date() if end_date else today

    # Convert to datetimes for accurate filtering
    start_dt = datetime.combine(start, time.min)
    end_dt = datetime.combine(end, time.max)

    TeamLeader = aliased(Agent)

    # Aggregate team budgets (sum of agent budgets only)
    budgets = dict(
        db.session.query(
            Agent.team_leader_id,
            func.coalesce(func.sum(Agent.monthly_budget), 0.0)
        )
        .filter(Agent.role != 'Team Leader')
        .group_by(Agent.team_leader_id)
        .all()
    )

    # Loans + agent counts by leader with date filter
    loan_stats = (
        db.session.query(
            TeamLeader.id.label('leader_id'),
            TeamLeader.name.label('leader_name'),
            func.count(distinct(Agent.id)).label('num_agents'),
            func.count(LoanApplication.id).label('applications'),
            func.coalesce(func.sum(LoanApplication.loan_amount), 0.0).label('total_loan_amount')
        )
        .filter(TeamLeader.role == 'Team Leader')
        .outerjoin(
            Agent,
            and_(
                Agent.team_leader_id == TeamLeader.id,
                Agent.role != 'Team Leader'
            )
        )
        .outerjoin(
            LoanApplication,
            and_(
                LoanApplication.agent_id == Agent.id,
                LoanApplication.created_at >= start_dt,
                LoanApplication.created_at <= end_dt
            )
        )
        .group_by(TeamLeader.id, TeamLeader.name)
        .order_by(TeamLeader.name)
        .all()
    )

    team_stats = []
    for row in loan_stats:
        team_budget = float(budgets.get(row.leader_id, 0.0))
        achievement = round((row.total_loan_amount / team_budget) * 100, 2) if team_budget else 0.0

        team_stats.append({
            "team_leader_id": row.leader_id,
            "team_leader_name": row.leader_name,
            "num_agents": row.num_agents,
            "applications": row.applications,
            "total_loan_amount": float(row.total_loan_amount),
            "team_budget": team_budget,
            "achievement": achievement
        })

    return render_template(
        "dashboard/team_leader_dashboard.html",
        stats=team_stats,
        active_tab="team"
    )

from flask import jsonify
from datetime import datetime, date, timedelta
from calendar import monthrange
from sqlalchemy import func


@app.route('/notifications/sales-summary')
def sales_summary_notification():
    today = date.today()
    start_of_month = today.replace(day=1)
    start_of_today = datetime.combine(today, time.min)
    end_of_today = datetime.combine(today, time.max)

    start_of_month_dt = datetime.combine(start_of_month, datetime.min.time())
    end_of_today_dt = datetime.combine(today, datetime.max.time())

    # Helper to calculate working days
    def working_days(start, end):
        return sum(1 for n in range((end - start).days + 1)
                   if (start + timedelta(n)).weekday() < 5)

    working_days_passed = working_days(start_of_month, today)
    total_days_in_month = monthrange(today.year, today.month)[1]
    total_working_days = working_days(start_of_month,
                                      start_of_month.replace(day=total_days_in_month))

    # Query all active agents
    agents = Agent.query.filter(Agent.active.is_(True)).all()
    agent_ids = [a.id for a in agents]

    # Aggregate loans per agent
    loans_per_agent = (
        db.session.query(
            LoanApplication.agent_id,
            func.count(LoanApplication.id).label("applications"),
            func.coalesce(func.sum(LoanApplication.loan_amount), 0).label("total_loan_amount"),
            func.coalesce(
                func.sum(
                    case(
                            (
                                (LoanApplication.created_at >= start_of_today) &
                                (LoanApplication.created_at <= end_of_today),
                                LoanApplication.loan_amount
                            )
                        ,
                        else_=0
                    )
                ),
                0
            ).label("todays_sales")
        )
        .filter(LoanApplication.agent_id.in_(agent_ids))
        .filter(LoanApplication.created_at >= start_of_month_dt)
        .filter(LoanApplication.created_at <= end_of_today_dt)
        .group_by(LoanApplication.agent_id)
        .all()
    )

    # Build agent table including agents with no loans
    agent_table = []
    for agent in agents:
        row = next((r for r in loans_per_agent if r.agent_id == agent.id), None)
        applications = row.applications if row else 0
        total_loan = float(row.total_loan_amount) if row else 0
        today_loan = float(row.todays_sales) if row else 0
        active_days = applications  # or custom logic if you track actual working days per agent
        applications_per_day = applications / active_days if active_days else 0
        agent_table.append({
            "agent_name": agent.name,
            "region": agent.region,
            "district": agent.district,
            "applications": applications,
            "applications_per_day": round(applications_per_day, 2),
            "active_days": active_days,
            "total_loan_amount": total_loan,
            "monthly_budget": agent.monthly_budget,
            "achievement_percent": round((total_loan / agent.monthly_budget * 100) if agent.monthly_budget else 0, 2),
            "todays_sales": today_loan
        })

    # Total sales
    todays_sales = sum(a["todays_sales"] for a in agent_table)
    mtd_sales = sum(a["total_loan_amount"] for a in agent_table)
    total_budget = sum(a.monthly_budget for a in agents)
    budget_achievement = (mtd_sales / total_budget * 100) if total_budget else 0
    working_days_ratio = (working_days_passed / total_working_days * 100) if total_working_days else 0

    return jsonify({
        "today_sales": round(todays_sales, 2),
        "mtd_sales": round(mtd_sales, 2),
        "total_budget": round(total_budget, 2),
        "achievement_percent": round(budget_achievement, 2),
        "working_days_percent": round(working_days_ratio, 2),
        "on_track": budget_achievement >= working_days_ratio,
        "agent_table": agent_table
    })

@app.route('/agents/team/add', methods=['GET', 'POST'])
def add_team_with_agents():
    if request.method == 'POST':
        try:
            # Leader: existing or new
            existing_leader_id = request.form.get('existing_leader_id')
            if existing_leader_id:
                leader = Agent.query.get(int(existing_leader_id))
                print(f"Using existing team leader: {leader.name} (ID: {leader.id})")
            else:
                # Prevent duplicate leaders by phone or name
                existing_leader = Agent.query.filter(
                    (Agent.contact == request.form.get('leader_phone')) |
                    (Agent.name.ilike(request.form['leader_name']))
                ).first()

                if existing_leader:
                    leader = existing_leader
                    print(f"Using existing leader (duplicate detected): {leader.name}")
                else:
                    leader = Agent(
                        name=request.form['leader_name'].strip(),
                        contact=request.form.get('leader_phone').strip(),
                        email=request.form.get('leader_email').strip(),
                        role='Team Leader'
                    )
                    db.session.add(leader)
                    db.session.flush()  # assigns leader.id
                    print(f"Created new team leader: {leader.name} (ID: {leader.id})")

            # Fetch submitted agent data
            names = request.form.getlist('agent_name[]')
            phones = request.form.getlist('agent_phone[]')
            emails = request.form.getlist('agent_email[]')
            districts = request.form.getlist('agent_district[]')
            regions = request.form.getlist('agent_region[]')
            budgets = request.form.getlist('agent_budget[]')

            print("Agents submitted:", names)

            added_agents = 0
            for name, phone, email, district, region, budget_str in zip(
                names, phones, emails, districts, regions, budgets
            ):
                if not name.strip():
                    print("Skipped agent with empty name.")
                    continue

                # Check for duplicates (by phone or name)
                existing_agent = Agent.query.filter(
                    (Agent.contact == phone.strip()) |
                    (Agent.name.ilike(name.strip()))
                ).first()

                if existing_agent:
                    print(f"⚠️ Skipping duplicate agent: {existing_agent.name} ({existing_agent.contact})")
                    continue

                try:
                    budget = float(budget_str) if budget_str else 0.0
                except ValueError:
                    budget = 0.0

                agent = Agent(
                    name=name.strip(),
                    contact=phone.strip(),
                    email=email.strip(),
                    district=district.strip(),
                    region=region.strip(),
                    monthly_budget=budget,
                    role='Agent',
                    team_leader_id=leader.id
                )
                db.session.add(agent)
                added_agents += 1
                print(f"✅ Added agent: {agent.name}, team leader: {leader.name}")

            if added_agents == 0:
                raise Exception("No valid agents submitted (all duplicates or empty).")

            db.session.commit()
            flash(f"Team created with {added_agents} agent(s)!", "success")
            return redirect(url_for('view_agents'))

        except Exception as e:
            db.session.rollback()
            flash(f"Error creating team: {str(e)}", "danger")
            print("Exception:", e)

    # GET
    team_leaders = Agent.query.filter_by(role='Team Leader').order_by(Agent.name).all()
    return render_template('agents/add_team_with_agents.html', team_leaders=team_leaders)
    

@app.route('/agents')
@login_required
@role_required('admin')  # Optional: if you want to restrict access
def view_agents():
    agents = Agent.query \
        .filter_by(role='Agent') \
        .order_by(Agent.name.asc()) \
        .all()

    return render_template('agents/view_agents.html', agents=agents)



def get_sales_notification():
    today = date.today()
    start_of_month = today.replace(day=1)

    total_days = calendar.monthrange(today.year, today.month)[1]
    working_days = [
        start_of_month + timedelta(days=i)
        for i in range(total_days)
        if (start_of_month + timedelta(days=i)).weekday() < 5
    ]

    days_passed = [d for d in working_days if d <= today]

    today_sales = db.session.query(func.sum(LoanApplication.loan_amount)) \
        .filter(func.date(LoanApplication.created_at) == today).scalar() or 0

    mtd_sales = db.session.query(func.sum(LoanApplication.loan_amount)) \
        .filter(LoanApplication.created_at >= start_of_month).scalar() or 0

    total_budget = db.session.query(func.sum(Agent.monthly_budget)).scalar() or 0

    sales_pct = (mtd_sales / total_budget * 100) if total_budget else 0
    time_pct = (len(days_passed) / len(working_days) * 100) if working_days else 0

    return {
        "today_sales": round(today_sales, 2),
        "mtd_sales": round(mtd_sales, 2),
        "total_budget": round(total_budget, 2),
        "sales_pct": round(sales_pct, 1),
        "time_pct": round(time_pct, 1),
        "working_days": len(working_days),
        "days_passed": len(days_passed),
        "report_date": today.strftime("%B %d, %Y")
    }

def get_historical_comparisons(today):
    """Safe historical comparisons with all required fields"""
    try:
        start_of_month = today.replace(day=1)
        
        # Last month period
        if today.month == 1:
            last_month = today.replace(year=today.year-1, month=12)
        else:
            last_month = today.replace(month=today.month-1)
        
        start_of_last_month = last_month.replace(day=1)
        
        # Last year period
        last_year = today.replace(year=today.year-1)
        start_of_last_year = last_year.replace(day=1)
        
        # Calculate days
        _, total_days = calendar.monthrange(today.year, today.month)
        current_days = today.day
        
        return {
            'start_of_month': start_of_month,
            'start_of_last_month': start_of_last_month,
            'start_of_last_year': start_of_last_year,
            'total_days': total_days,
            'current_days': current_days,
            'last_month_days': min(today.day, calendar.monthrange(last_month.year, last_month.month)[1]),
            'last_year_days': min(today.day, calendar.monthrange(last_year.year, last_year.month)[1])
        }
    except Exception as e:
        current_app.logger.error(f"Error in date calculations: {str(e)}")
        return {
            'start_of_month': today.replace(day=1),
            'total_days': 30,
            'current_days': today.day,
            # Add safe defaults here if needed
        }

def get_today_sales(today):
    """Get today's sales total"""
    return db.session.query(
        func.coalesce(func.sum(LoanApplication.loan_amount), 0.0)
    ).filter(
        func.date(LoanApplication.created_at) == today
    ).scalar()

def get_mtd_sales(start_of_month):
    """Get month-to-date sales total"""
    return db.session.query(
        func.coalesce(func.sum(LoanApplication.loan_amount), 0.0)
    ).filter(
        LoanApplication.created_at >= start_of_month
    ).scalar()

def get_total_budget():
    return db.session.query(
        func.coalesce(func.sum(Agent.monthly_budget), 0.0)
    ).scalar()

def calculate_sales_percentage(sales, budget):
    """Calculate sales achievement percentage"""
    return (sales / budget * 100) if budget > 0 else 0.0

def calculate_time_percentage(comparisons):
    """Calculate time progression percentage"""
    return (comparisons['current_days'] / comparisons['total_days'] * 100) if comparisons['total_days'] > 0 else 0.0

from flask import render_template, jsonify, request
from datetime import datetime, date, timedelta
from sqlalchemy import case, func, and_, extract, or_

SAMPLE_SALES = [
    {"category": "Youth", "sales_count": 18, "total_sales": 94000000},
    {"category": "Male", "sales_count": 5, "total_sales": 25000000},
    {"category": "Female", "sales_count": 10, "total_sales": 50000000},
    # "Other" intentionally left out to test zero fill
]


from flask import render_template, request
from datetime import datetime, date, timedelta
from sqlalchemy import case, func, literal

@app.route("/sales-by-gender")
def gender_dashboard():
    # Get filter parameters
    start_date_str = request.args.get("start_date")
    end_date_str = request.args.get("end_date")
    
    # Parse dates with validation
    today = date.today()
    
    # Default to current month
    first_day = today.replace(day=1)
    last_day = (today.replace(month=today.month % 12 + 1, day=1) - timedelta(days=1))
    
    try:
        if start_date_str:
            start_date = datetime.strptime(start_date_str, "%Y-%m-%d").date()
        else:
            start_date = first_day
            start_date_str = first_day.strftime("%Y-%m-%d")
            
        if end_date_str:
            end_date = datetime.strptime(end_date_str, "%Y-%m-%d").date()
        else:
            end_date = last_day
            end_date_str = last_day.strftime("%Y-%m-%d")
            
    except (ValueError, TypeError):
        # If date parsing fails, use default dates
        start_date = first_day
        end_date = last_day
        start_date_str = first_day.strftime("%Y-%m-%d")
        end_date_str = last_day.strftime("%Y-%m-%d")

    # Calculate age based on year only (simplified for SQLite)
    birth_year = func.cast(func.substr(Customer.dob, 1, 4), db.Integer)
    age = today.year - birth_year
    
    # Define category logic
    category = case(
        (age < 35, literal('Youth')),
        (Customer.gender.ilike('male'), literal('Male')),
        (Customer.gender.ilike('female'), literal('Female')),
        else_=literal('Other')
    ).label('category')

    # Build query
    query = db.session.query(
        category,
        func.count(LoanApplication.id).label('sales_count'),
        func.coalesce(func.sum(LoanApplication.loan_amount), 0).label('total_sales')
    ).join(Customer, Customer.id == LoanApplication.customer_id)

    # Apply date filters
    if start_date:
        query = query.filter(LoanApplication.created_at >= start_date)
    if end_date:
        next_day = end_date + timedelta(days=1)
        query = query.filter(LoanApplication.created_at < next_day)

    # Group and execute
    results = query.group_by(category).all()
    
    # Prepare final results with all categories
    all_categories = ["Youth", "Male", "Female", "Other"]
    category_data = {r[0]: r for r in results}
    
    final_results = []
    total_sales_count = 0
    total_sales_amount = 0.0
    
    for cat in all_categories:
        if cat in category_data:
            sales_count = int(category_data[cat][1])
            sales_amount = float(category_data[cat][2])
            final_results.append({
                "category": cat,
                "sales_count": sales_count,
                "total_sales": sales_amount
            })
            total_sales_count += sales_count
            total_sales_amount += sales_amount
        else:
            final_results.append({
                "category": cat,
                "sales_count": 0,
                "total_sales": 0.0
            })
    
    # Format numbers as strings with commas
    def format_number(num):
        return f"{num:,.0f}"
    
    formatted_results = []
    for item in final_results:
        formatted_results.append({
            "category": item["category"],
            "sales_count": format_number(item["sales_count"]),
            "total_sales": format_number(item["total_sales"])
        })
    
    return render_template(
        "sales_by_gender.html",
        data=formatted_results,
        total_sales_count=format_number(total_sales_count),
        total_sales_amount=format_number(total_sales_amount),
        start_date=start_date_str,
        end_date=end_date_str,
        active_tab='gender'
    )

from datetime import date, datetime, time, timedelta
from sqlalchemy import func

def _apply_agent_filters_to_loan_query(q, filters):
    """Join to Agent and apply region/district/team_leader filters."""
    if not filters:
        return q
    q = q.join(Agent, Agent.id == LoanApplication.agent_id)
    if filters.get('region'):
        q = q.filter(Agent.region == filters['region'])
    if filters.get('district'):
        q = q.filter(Agent.district == filters['district'])
    if filters.get('team_leader_id'):
        q = q.filter(Agent.team_leader_id == filters['team_leader_id'])
    # Exclude loans that were (accidentally) assigned to a Team Leader if you never want that counted:
    q = q.filter(Agent.role != 'Team Leader')
    return q

def _day_bounds(d: date):
    start = datetime.combine(d, time.min)  # 00:00:00
    end = datetime.combine(d, time.max)    # 23:59:59.999999
    return start, end


def get_sales_data(filters=None):
    with app.app_context():
        today = date.today()
        try:
            cmp = get_historical_comparisons(today)

            today_sales = get_today_sales(today, filters)
            mtd_sales   = get_mtd_sales(cmp['start_of_month'], filters)
            total_budget = get_total_budget(filters)

            sales_pct = calculate_sales_percentage(mtd_sales, total_budget)
            time_pct  = calculate_time_percentage(cmp)

            # Same elapsed days comparison
            days_so_far = cmp['current_days']
            start_last_month = cmp['start_of_last_month']
            start_last_year  = cmp['start_of_last_year']

            last_month_sales = get_mtd_sales(start_last_month, filters={
                **(filters or {}),
                # bound by same elapsed days:
                '__end__': start_last_month + timedelta(days=days_so_far)  # handled below if you keep a single entrypoint
            })
            last_year_sales = get_mtd_sales(start_last_year, filters={
                **(filters or {}),
                '__end__': start_last_year + timedelta(days=days_so_far)
            })

            # If you keep the single get_mtd_sales signature, add support for filters.get('__end__'):
            # (see small tweak below)

            last_month_sales_pct = calculate_sales_percentage(last_month_sales, total_budget)
            last_year_sales_pct  = calculate_sales_percentage(last_year_sales, total_budget)

            team_leaders = get_team_leader_performance(cmp, filters)

            return {
                "today_sales": float(today_sales),
                "mtd_sales": float(mtd_sales),
                "total_budget": float(total_budget),
                "sales_pct": round(sales_pct, 1),
                "time_pct": round(time_pct, 1),
                "last_month_sales": float(last_month_sales),
                "last_year_sales": float(last_year_sales),
                "last_month_sales_pct": round(last_month_sales_pct, 1),
                "last_year_sales_pct": round(last_year_sales_pct, 1),
                "working_days": int(cmp['total_days']),
                "days_passed": int(cmp['current_days']),
                "report_date": today.strftime("%B %d, %Y"),
                "team_leaders": team_leaders,
                "is_valid": True
            }
        except Exception as e:
            app.logger.error(f"Sales data error: {str(e)}", exc_info=True)
            return get_fallback_sales_data(today)

def get_today_sales(today: date, filters=None):
    start, end = _day_bounds(today)
    q = db.session.query(func.coalesce(func.sum(LoanApplication.loan_amount), 0.0)) \
                  .filter(LoanApplication.created_at >= start,
                          LoanApplication.created_at < end)
    q = _apply_agent_filters_to_loan_query(q, filters)
    return q.scalar() or 0.0

def get_mtd_sales(start_date: date, filters=None):
    # Allow optional hard end via filters['__end__']
    hard_end = None
    if filters and filters.get('__end__'):
        hard_end = filters['__end__']
    _, default_end = _day_bounds(date.today())
    end = hard_end or default_end

    q = db.session.query(func.coalesce(func.sum(LoanApplication.loan_amount), 0.0)) \
                  .filter(LoanApplication.created_at >= start_date,
                          LoanApplication.created_at < end)
    q = _apply_agent_filters_to_loan_query(q, filters)
    return q.scalar() or 0.0

def get_team_leader_performance(comparisons, filters=None):
    """Per-leader MTD vs same-period last month/year, using only agents (no leaders)."""
    start_mtd = comparisons['start_of_month']
    # Compare apples-to-apples: same number of elapsed *days* as current month
    days_so_far = comparisons['current_days']
    start_last_month = comparisons['start_of_last_month']
    end_last_month   = start_last_month + timedelta(days=days_so_far)
    start_last_year  = comparisons['start_of_last_year']
    end_last_year    = start_last_year + timedelta(days=days_so_far)

    leaders = Agent.query.filter(Agent.role == "Team Leader").all()
    perf = []

    for leader in leaders:
        # Agents in this team (exclude the leader)
        agent_ids = [a.id for a in Agent.query
                     .filter(Agent.team_leader_id == leader.id,
                             Agent.role != 'Team Leader',
                             Agent.active.is_(True)).all()]

        if not agent_ids:
            agent_ids = [-1]  # prevent empty IN() SQL

        def _sum_sales(start_dt, end_dt):
            q = db.session.query(func.coalesce(func.sum(LoanApplication.loan_amount), 0.0)) \
                          .filter(LoanApplication.created_at >= start_dt,
                                  LoanApplication.created_at < end_dt,
                                  LoanApplication.agent_id.in_(agent_ids))
            # Optional higher-level filters can further narrow by region/district if you want:
            if filters:
                if filters.get('region'):
                    q = q.join(Agent, Agent.id == LoanApplication.agent_id).filter(Agent.region == filters['region'])
                if filters.get('district'):
                    q = q.join(Agent, Agent.id == LoanApplication.agent_id).filter(Agent.district == filters['district'])
            return q.scalar() or 0.0

        # MTD current
        today_start, today_end = _day_bounds(date.today())
        team_sales_mtd = _sum_sales(start_mtd, today_end)

        team_apps_mtd = db.session.query(func.count(LoanApplication.id)).filter(
            LoanApplication.created_at >= start_mtd,
            LoanApplication.created_at < today_end,
            LoanApplication.agent_id.in_(agent_ids)
        ).scalar() or 0

        team_budget = db.session.query(func.coalesce(func.sum(Agent.monthly_budget), 0.0)) \
            .filter(Agent.id.in_(agent_ids)).scalar() or 0.0

        ach = (team_sales_mtd / team_budget * 100.0) if team_budget > 0 else 0.0

        # Last month / last year (same elapsed days)
        last_month_sales = _sum_sales(start_last_month, end_last_month)
        last_year_sales  = _sum_sales(start_last_year,  end_last_year)
        last_month_ach = (last_month_sales / team_budget * 100.0) if team_budget > 0 else 0.0
        last_year_ach  = (last_year_sales  / team_budget * 100.0) if team_budget > 0 else 0.0

        status = "exceeded" if ach >= 100 else "on-track" if ach >= 75 else "needs-improvement"

        perf.append({
            'id': leader.id,
            'name': leader.name,
            'applications': int(team_apps_mtd),
            'sales': float(team_sales_mtd),
            'team_budget': float(team_budget),
            'achievement': round(ach, 1),
            'last_month_achievement': round(last_month_ach, 1),
            'last_year_achievement': round(last_year_ach, 1),
            'status': status
        })

    perf.sort(key=lambda x: x['achievement'], reverse=True)
    return perf


def get_total_budget(filters=None):
    q = db.session.query(func.coalesce(func.sum(Agent.monthly_budget), 0.0)) \
                  .filter(Agent.role != 'Team Leader', Agent.active.is_(True))
    if filters:
        if filters.get('region'):
            q = q.filter(Agent.region == filters['region'])
        if filters.get('district'):
            q = q.filter(Agent.district == filters['district'])
        if filters.get('team_leader_id'):
            q = q.filter(Agent.team_leader_id == filters['team_leader_id'])
    return q.scalar() or 0.0



def get_fallback_sales_data(today):
    """Get fallback data when sales data retrieval fails"""
    comparisons = get_historical_comparisons(today)
    return {
        "today_sales": 0.0,
        "mtd_sales": 0.0,
        "total_budget": 0.0,
        "sales_pct": 0.0,
        "time_pct": 0.0,
        "last_month_sales": 0.0,
        "last_year_sales": 0.0,
        "last_month_sales_pct": 0.0,
        "last_year_sales_pct": 0.0,
        "working_days": comparisons.get('total_days', 30),
        "days_passed": comparisons.get('current_days', min(today.day, 30)),
        "report_date": today.strftime("%B %d, %Y"),
        "team_leaders": [],
        "is_valid": False
    }
        
def generate_performance_table(data, title, columns):
    """Generate HTML table for performance data"""
    rows = ''.join(
        f"<tr><td>{item[columns[0]]}</td>"
        f"<td>{item[columns[1]]:,.2f}</td>"
        f"<td>{item[columns[2]]}</td>"
        f"<td>{item[columns[3]]:,.1f}%</td></tr>"
        for item in data
    )
    
    return f"""
    <h3>{title}</h3>
    <table class="performance-table">
        <tr>
            <th>{columns[0].title()}</th>
            <th>{columns[1].replace('_', ' ').title()}</th>
            <th>{columns[2].replace('_', ' ').title()}</th>
            <th>{columns[3].replace('_', ' ').title()}</th>
        </tr>
        {rows}
    </table>
    """




                
def test_db():
    try:
        from app import db
        db.session.execute('SELECT 1')  # Simple test query
        return "Database connection works!"
    except Exception as e:
        return f"Database error: {str(e)}", 500

@app.route('/test-email-simple')
def test_email_simple():
    result = send_sales_notification_email()
    return f"Test email triggered! Result: {result}"

@app.route('/check-tables')
def check_tables():
    try:
        tables = db.session.execute(text("SELECT name FROM sqlite_master WHERE type='table'")).fetchall()
        return f"Existing tables: {[t[0] for t in tables]}"
    except Exception as e:
        return f"Error checking tables: {str(e)}", 500

@app.route('/create-sales-table')
def create_sales_table():
    try:
        db.session.execute(text("""
            CREATE TABLE IF NOT EXISTS sales (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                amount DECIMAL(10,2) NOT NULL,
                sale_date DATE NOT NULL,
                region VARCHAR(50),
                category VARCHAR(50)
            """))
        db.session.commit()
        return "Sales table created successfully!"
    except Exception as e:
        return f"Error creating table: {str(e)}", 500


@app.route('/test-db-simple')
def test_db_simple():
    try:
        # Correct database query with text() wrapper
        result = db.session.execute(text('SELECT 1')).scalar()
        return f"Database connection works! Result: {result}"
    except Exception as e:
        return f"Database error: {str(e)}", 500
    
def send_minute_notification():
    with app.app_context():
        try:
            # Create test notification
            notification = Notification(
                message=f"Test notification at {datetime.utcnow()}",
                type='info',
                recipient_id=None  # Global notification
            )
            db.session.add(notification)
            db.session.commit()
            app.logger.info("Sent minute notification")
        except Exception as e:
            app.logger.error(f"Notification error: {str(e)}")

def get_growth_indicator(growth):
    """Return growth indicator with appropriate icon"""
    if growth > 0:
        return f"<span style='color:#28a745'>▲ {growth:,.1f}%</span>"
    elif growth < 0:
        return f"<span style='color:#dc3545'>▼ {growth:,.1f}%</span>"
    return f"<span>{growth:,.1f}%</span>"

def get_growth_class(growth):
    """Return CSS class for growth value"""
    if growth > 0:
        return "growth-positive"
    elif growth < 0:
        return "growth-negative"
    return ""

# Initialize scheduler

# Test route for manual triggering
@app.route('/test-report')
def test_report():
    result = send_sales_notification_email()
    return "Test report sent!" if result else "Failed to send test report"

@app.route('/test-sales-data')
def test_sales_data():
    try:
        data = get_sales_data()
        return jsonify({
            'status': 'success',
            'data': {
                'today_sales': data['today_sales'],
                'mtd_sales': data['mtd_sales']
            }
        })
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/test-email-system')
def test_email_system():
    result = send_sales_notification_email()
    return jsonify({'status': 'success' if result else 'error'})



@app.route('/dashboard/analytics')
def sales_charts():
    return render_template("dashboard/sales_charts.html", active_tab="analytics")

from flask import jsonify

@app.route('/api/loans-by-region')
def api_loans_by_region():
    region = request.args.get('region')
    district = request.args.get('district')
    team_leader = request.args.get('team_lead')

    query = db.session.query(
        Agent.region,
        func.sum(LoanApplication.loan_amount).label('total_loan')
    ).join(LoanApplication, LoanApplication.agent_id == Agent.id)

    if region:
        query = query.filter(Agent.region == region)
    if district:
        query = query.filter(Agent.district == district)
    if team_leader:
        query = query.filter(Agent.team_leader == team_leader)

    query = query.group_by(Agent.region)
    data = query.all()

    return jsonify({
        "labels": [r.region for r in data],
        "values": [float(r.total_loan or 0) for r in data]
    })

def reconcile_loan_vs_payroll(loan_id):
    loan = LoanApplication.query.get(loan_id)
    mismatches = []

    for sched in loan.repayment_schedules:
        if sched.status == 'paid':
            continue  # skip already paid

        payroll = PayrollDeduction.query.filter_by(
            loan_id=loan.id,
            deduction_date=sched.due_date
        ).first()

        if not payroll or payroll.amount < sched.expected_amount:
            mismatches.append({
                "instalment": sched.instalment_no,
                "due_date": sched.due_date,
                "expected": sched.expected_amount,
                "deducted": payroll.amount if payroll else 0
            })

    return mismatches

def reconcile_vote_receipts(vote_id, month):
    vote = Vote.query.get(vote_id)
    start = month.replace(day=1)
    end = (start + relativedelta(months=1)) - timedelta(days=1)

    expected = db.session.query(func.sum(Payment.amount)).join(LoanApplication).filter(
        LoanApplication.vote_id == vote.id,
        Payment.created_at >= start,
        Payment.created_at <= end,
        Payment.status == 'successful'
    ).scalar() or 0

    received = db.session.query(func.sum(CashReceipt.amount)).filter(
        CashReceipt.vote_id == vote.id,
        CashReceipt.received_date >= start,
        CashReceipt.received_date <= end
    ).scalar() or 0

    return {
        "vote_code": vote.code,
        "expected": expected,
        "received": received,
        "discrepancy": expected - received
    }


@app.route('/api/loans-by-district')
def api_loans_by_district():
    from sqlalchemy import func

    data = (
        db.session.query(
            Agent.district,
            func.count(LoanApplication.id).label('applications')
        )
        .join(LoanApplication, LoanApplication.agent_id == Agent.id)
        .group_by(Agent.district)
        .all()
    )

    labels = [row.district for row in data]
    values = [row.applications for row in data]

    return jsonify({"labels": labels, "values": values})


@app.route('/api/average-ticket-size')
def api_average_ticket_size():
    from sqlalchemy import func

    data = (
        db.session.query(
            Agent.region,
            func.avg(LoanApplication.loan_amount).label('avg_ticket')
        )
        .join(LoanApplication, LoanApplication.agent_id == Agent.id)
        .group_by(Agent.region)
        .all()
    )

    labels = [row.region for row in data]
    values = [round(float(row.avg_ticket or 0), 2) for row in data]

    return jsonify({"labels": labels, "values": values})



@app.route('/debug/storage')
def debug_storage():
    return {
        'UPLOAD_FOLDER': app.config.get('UPLOAD_FOLDER', ''),
        'CWD': os.getcwd(),
        'INSTANCE_PATH': app.instance_path,
        'ABSOLUTE_UPLOAD_PATH': os.path.abspath(app.config.get('UPLOAD_FOLDER', ''))
    }

@app.route('/repair/documents', methods=['POST'])
@role_required('admin')
def repair_documents():
    """Fix document paths in database and move files to correct location"""
    try:
        updated_count = 0
        errors = []
        base_path = os.path.join(app.instance_path, 'documents')
        
        # Ensure the new location exists
        os.makedirs(base_path, exist_ok=True)
        
        # Get all documents
        documents = Document.query.all()
        
        for doc in documents:
            try:
                # Skip if path is already correct
                if doc.path and 'instance/documents' in doc.path.replace('\\', '/'):
                    continue
                    
                # Handle missing paths
                if not doc.path:
                    # Try to find by filename in the new location
                    possible_path = os.path.join(base_path, doc.filename)
                    if os.path.exists(possible_path):
                        doc.path = os.path.relpath(possible_path, start=app.root_path)
                        updated_count += 1
                    continue
                
                # Get current absolute path
                if os.path.isabs(doc.path):
                    current_path = doc.path
                else:
                    current_path = os.path.join(app.root_path, doc.path)
                
                # Skip if file doesn't exist
                if not os.path.exists(current_path):
                    errors.append(f"Document {doc.id}: File not found at {current_path}")
                    continue
                    
                # New path in instance folder
                new_filename = f"{doc.customer_id}_{doc.id}_{doc.filename}"
                new_path = os.path.join(base_path, new_filename)
                
                # Move file
                shutil.move(current_path, new_path)
                
                # Update database
                doc.path = os.path.relpath(new_path, start=app.root_path)
                doc.filename = new_filename  # Update filename to include IDs
                updated_count += 1
                
            except Exception as e:
                errors.append(f"Document {doc.id}: {str(e)}")
        
        db.session.commit()
        return jsonify({
            'status': 'success',
            'updated_count': updated_count,
            'total_documents': len(documents),
            'base_path': base_path,
            'new_location': os.path.relpath(base_path, start=app.root_path),
            'errors': errors
        })
        
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/repair/documents/page')
@role_required('admin')
def repair_documents_page():
    return render_template('repair_documents.html',
        instance_path=app.instance_path,
        root_path=app.root_path,
        upload_folder=app.config.get('UPLOAD_FOLDER', ''),
        absolute_path=os.path.join(app.instance_path, 'documents')
    )

@app.route('/repair/paths')
@role_required('admin')
def repair_paths():
    updated = convert_legacy_paths()
    return jsonify({
        'status': 'success',
        'updated': updated,
        'upload_folder': app.config['UPLOAD_FOLDER'],
        'instance_path': app.instance_path
    })

@app.route('/debug/documents/page')
@role_required('admin')
def debug_documents_page():
    """Advanced document debugger page"""
    return render_template('debug_documents.html')  

@app.route('/verify/documents')
@role_required('admin')
def verify_documents():
    """Verify all document paths"""
    docs = Document.query.all()
    results = []
    
    for doc in docs:
        # Get absolute path
        if doc.path:
            if os.path.isabs(doc.path):
                abs_path = doc.path
            else:
                abs_path = os.path.join(app.root_path, doc.path)
            exists = os.path.exists(abs_path)
        else:
            abs_path = None
            exists = False
        
        results.append({
            'id': doc.id,
            'filename': doc.filename,
            'stored_path': doc.path,
            'absolute_path': abs_path,
            'exists': exists,
            'customer_id': doc.customer_id,
            'loan_id': doc.loan_id
        })
    
    return jsonify({
        'instance_path': app.instance_path,
        'root_path': app.root_path,
        'upload_folder': app.config.get('UPLOAD_FOLDER', ''),
        'documents': results
    })

@app.route('/debug/documents')
@role_required('admin')
def debug_documents_api():
    """API endpoint for document debugging"""
    customer_id = request.args.get('customer_id')
    loan_id = request.args.get('loan_id')
    
    results = {
        'customer': None,
        'loan': None,
        'documents': [],
        'instance_path': app.instance_path,
        'root_path': app.root_path,
        'upload_folder': app.config.get('UPLOAD_FOLDER', '')
    }
    
    # Get customer documents
    if customer_id:
        try:
            customer = Customer.query.get(customer_id)
            if customer:
                results['customer'] = {
                    'id': customer.id,
                    'name': f"{customer.first_name} {customer.last_name}",
                    'file_number': customer.file_number
                }
                
                # Get all documents for customer
                for doc in customer.customer_documents:
                    abs_path = doc.absolute_path
                    results['documents'].append({
                        'id': doc.id,
                        'filename': doc.filename,
                        'filetype': doc.filetype,
                        'stored_path': doc.path,
                        'absolute_path': abs_path,
                        'exists': os.path.exists(abs_path) if abs_path else False
                    })
        except Exception as e:
            results['error'] = str(e)
    
    # Get loan documents
    if loan_id:
        try:
            loan = LoanApplication.query.get(loan_id)
            if loan:
                results['loan'] = {
                    'id': loan.id,
                    'loan_number': loan.loan_number,
                    'status': loan.application_status,
                    'customer_id': loan.customer_id
                }
                
                # Get all documents for loan
                for doc in loan.documents:
                    abs_path = doc.absolute_path
                    results['documents'].append({
                        'id': doc.id,
                        'filename': doc.filename,
                        'filetype': doc.filetype,
                        'stored_path': doc.path,
                        'absolute_path': abs_path,
                        'exists': os.path.exists(abs_path) if abs_path else False
                    })
        except Exception as e:
            results['error'] = str(e)
    
    return jsonify(results)

@app.cli.command('repair-docs')
def repair_docs_command():
    """Command line document repair tool"""
    from app import repair_documents
    with app.test_request_context():
        response = repair_documents()
        data = response.get_json()
        print(f"Repair Results:")
        print(f"Updated: {data.get('updated_count', 0)} documents")
        print(f"Total: {data.get('total_documents', 0)} documents")
        print(f"Base Path: {data.get('base_path', '')}")
        
        if errors := data.get('errors'):
            print("\nErrors:")
            for error in errors:
                print(f" - {error}")

@app.cli.command('migrate-docs')
def migrate_documents():
    """Migrate documents to proper location"""
    import shutil
    
    docs = Document.query.all()
    new_base = os.path.join(app.instance_path, 'documents')
    os.makedirs(new_base, exist_ok=True)
    
    migrated = 0
    for doc in docs:
        if not doc.path:
            continue
            
        try:
            # Get current absolute path
            if os.path.isabs(doc.path):
                current_path = doc.path
            else:
                current_path = os.path.join(app.root_path, doc.path)
            
            if not os.path.exists(current_path):
                continue
                
            # New path in instance folder
            new_path = os.path.join(new_base, os.path.basename(doc.path))
            
            # Skip if already in correct location
            if os.path.normpath(current_path) == os.path.normpath(new_path):
                continue
                
            # Move file
            shutil.move(current_path, new_path)
            
            # Update database with relative path
            doc.path = os.path.relpath(new_path, start=app.root_path)
            migrated += 1
            
        except Exception as e:
            app.logger.error(f"Error migrating document {doc.id}: {str(e)}")
    
    db.session.commit()
    print(f"Migrated {migrated} documents to {new_base}")

@app.route('/debug/documents')
@role_required('admin')
def debug_documents():
    """Advanced document debugging page"""
    return render_template('debug_documents.html')

from app import app, db

import smtplib

@app.route('/check-scheduler')
def check_scheduler():
    try:
        jobs = scheduler.get_jobs()
        return jsonify({
            "scheduler_running": scheduler.running,
            "active_jobs": [str(job) for job in jobs]
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/test-smtp')
def test_smtp():
    try:
        msg = Message(
            subject="TEST Email",
            recipients=["alfred@kwachafinancialservices.com"],  # ← Change to your email
            body="This is a test email from your Flask app"
        )
        mail.send(msg)
        return "Email sent! Check your inbox (and spam folder)"
    except Exception as e:
        return f"Error: {str(e)}"

def test_smtp_connection():
    try:
        with smtplib.SMTP_SSL('mail.kwachafinancialservices.com', 465) as server:
            server.login(
                'alfred@kwachafinancialservices.com',
                '~hHjb;m{urRh'
            )
            print("✅ SMTP login successful!")
        return True
    except Exception as e:
        print(f"❌ SMTP connection failed: {str(e)}")
        return False

from datetime import date
from sqlalchemy import and_


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

@app.route('/<path:path>')
def catch_all(path):
    return f"404: The URL /{path} was not found.", 404


from flask import render_template, request, flash, redirect, url_for
from sqlalchemy import func
from datetime import datetime

@app.route("/sales-by-month")
def sales_by_month():
    try:
        category = request.args.get("category", None)

        # Base query – include all loans, not just disbursed
        query = (
            db.session.query(
                func.strftime('%Y-%m', LoanApplication.created_at).label('month'),
                func.sum(LoanApplication.loan_amount).label('total_sales'),
                func.count(LoanApplication.id).label('loan_count')
            )
        )

        if category:
            query = query.filter(LoanApplication.category == category)

        monthly_data = (
            query.group_by(func.strftime('%Y-%m', LoanApplication.created_at))
                 .order_by(func.strftime('%Y-%m', LoanApplication.created_at).asc())
                 .all()
        )

        sales_stats = []
        total_sales = 0
        total_count = 0

        for row in monthly_data:
            try:
                # Human-friendly month label
                month_label = datetime.strptime(row.month, "%Y-%m").strftime("%B %Y")
            except Exception:
                month_label = row.month

            ticket_size = round((row.total_sales or 0) / (row.loan_count or 1), 2)
            total_sales += row.total_sales or 0
            total_count += row.loan_count

            sales_stats.append({
                "month": month_label,       # pretty label e.g. "April 2025"
                "raw_month": row.month,     # machine readable e.g. "2025-04"
                "total_sales": round(row.total_sales or 0, 2),
                "loan_count": row.loan_count,
                "ticket_size": ticket_size
            })

        # Totals row
        totals_row = {
            "month": "TOTAL",
            "total_sales": round(total_sales, 2),
            "loan_count": total_count,
            "ticket_size": round((total_sales / total_count), 2) if total_count > 0 else 0
        }

        return render_template(
            "sales_by_month.html",
            sales_stats=sales_stats,
            totals_row=totals_row,
            active_tab="monthly",
            category=category,
            categories=['civil_servant', 'private_sector', 'sme']
        )
    except Exception as e:
        flash(f"Error loading sales by month: {str(e)}", "danger")
        return redirect(url_for("sales_dashboard"))


import io
import pandas as pd
from flask import send_file

@app.route("/sales-by-month/download/<year_month>")
def download_sales_by_month(year_month):
    try:
        category = request.args.get("category", None)

        # Filter loans by year-month
        query = db.session.query(
            LoanApplication.id,
            LoanApplication.loan_amount,
            LoanApplication.category,
            LoanApplication.status,
            LoanApplication.created_at
        ).filter(func.strftime('%Y-%m', LoanApplication.created_at) == year_month)

        if category:
            query = query.filter(LoanApplication.category == category)

        loans = query.order_by(LoanApplication.created_at.asc()).all()

        if not loans:
            flash("No data available for this month", "warning")
            return redirect(url_for("sales_by_month", category=category))

        # Convert to dataframe
        df = pd.DataFrame([{
            "ID": l.id,
            "Loan Amount": l.loan_amount,
            "Category": l.category,
            "Status": l.status,
            "Created At": l.created_at.strftime("%Y-%m-%d")
        } for l in loans])

        # Write Excel to memory
        output = io.BytesIO()
        with pd.ExcelWriter(output, engine="xlsxwriter") as writer:
            df.to_excel(writer, index=False, sheet_name="SalesByMonth")

        output.seek(0)

        filename = f"sales_{year_month}.xlsx"
        return send_file(
            output,
            as_attachment=True,
            download_name=filename,
            mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        )
    except Exception as e:
        flash(f"Error exporting Excel: {str(e)}", "danger")
        return redirect(url_for("sales_by_month"))


def send_sales_notification_email(recipients=None, custom_message=None):
    """Enhanced email function with MWK formatting + notification tracking"""
    try:
        # 1. Get and format sales data
        sales_data = get_sales_data()
        
        # MWK Formatting (preserved from original)
        sales_data.update({
            'today_sales_mwk': f"MWK {sales_data['today_sales']:,.2f}",
            'mtd_sales_mwk': f"MWK {sales_data['mtd_sales']:,.2f}",
            'total_budget_mwk': f"MWK {sales_data['total_budget']:,.2f}",
            'custom_message': custom_message
        })

        # 2. Determine recipients (new logic)
        if not recipients:
            recipient_list = ["alfred@kwachafinancialservices.com", "sales@yourcompany.mw"]
        elif isinstance(recipients, str):
            recipient_list = [email.strip() for email in recipients.split(',')]
        elif isinstance(recipients, list):
            recipient_list = [email.strip() for email in recipients]
        else:
            raise ValueError("Invalid recipients format")

        # Keep a comma-separated string for database/logging
        email_recipients = ", ".join(recipient_list)

        # 3. Create notification record (new)
        notification = Notification(
            email_recipients=email_recipients,
            email_subject=f"Sales Report {sales_data['report_date']}",
            email_content=custom_message or "Automated sales report",
            message="Sales report dispatched",
            type="report"
        )
        db.session.add(notification)

        # 4. Send email (combined logic)
        template_name = 'email/sales_report.html'
        try:
            # Try HTML email first
            msg = Message(
                subject=notification.email_subject,
                recipients=recipient_list,
                html=render_template(template_name, notif=sales_data)
            )
            mail.send(msg)
            
            # If successful, update notification
            notification.email_sent = True
            notification.sent_at = datetime.utcnow()
            db.session.commit()
            
            current_app.logger.info(f"HTML email sent to {recipient_list}")
            return True

        except TemplateNotFound:
            # Fallback to text email (original logic with team leaders)
            team_leaders_section = ""
            if 'leaders' in sales_data and sales_data['leaders']:
                team_leaders_text = "\n".join([
                    f"- {leader['name']}: Sales - MK {leader['sales']:,.2f}, Achievement - {leader['achievement']}%"
                    for leader in sales_data['leaders']
                ])
                team_leaders_section = f"Team Leader Performance:\n{team_leaders_text}\n"
            
            body = f"""Sales Report ({sales_data['report_date']})

Today's Sales: {sales_data['today_sales_mwk']}
MTD Sales: {sales_data['mtd_sales_mwk']}
Budget Achievement: {sales_data['sales_pct']}% 

{team_leaders_section}

{custom_message or ''}
"""
            msg = Message(
                subject=notification.email_subject,
                recipients=recipient_list,
                body=body
            )
            mail.send(msg)
            notification.email_sent = True
            notification.sent_at = datetime.utcnow()
            db.session.commit()
            return True

    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Email failed: {str(e)}")
        return False    

def notify_arrears():
    """
    Notify admins of significant arrears (>30 days).
    """
    with app.app_context():
        arrears = Arrear.query.filter(
            Arrear.status == 'unresolved',
            Arrear.due_date < date.today() - timedelta(days=30)
        ).join(LoanApplication).join(Customer).all()
        
        if not arrears:
            return
        
        recipients = [user.email for user in User.query.filter_by(role_id=Role.query.filter_by(name='admin').first().id).all()]
        msg = Message(
            subject=f"Arrears Alert: {len(arrears)} Overdue Schedules",
            recipients=recipients,
            html=render_template(
                'email/arrears_notification.html',
                arrears=arrears,
                format_currency=format_currency
            )
        )
        try:
            mail.send(msg)
            app.logger.info(f"Arrears notification sent to {recipients}")
        except Exception as e:
            app.logger.error(f"Arrears notification failed: {str(e)}")


@app.route('/admin/vote_report', methods=['GET'])
@login_required
@role_required('admin')
def vote_report():
    votes = Vote.query.all()
    report = []
    for vote in votes:
        deductions = PayrollDeduction.query.filter(
            PayrollDeduction.vote_id == vote.id,
            PayrollDeduction.deduction_date >= date.today().replace(day=1)
        ).all()
        receipts = CashReceipt.query.filter(
            CashReceipt.vote_id == vote.id,
            CashReceipt.receipt_date >= date.today().replace(day=1)
        ).all()
        total_deducted = sum(d.amount for d in deductions)
        total_received = sum(r.amount for r in receipts)
        report.append({
            'vote': vote,
            'deduction_count': len(deductions),
            'total_deducted': total_deducted,
            'total_received': total_received,
            'discrepancy': total_deducted - total_received
        })
    return render_template(
        'admin/vote_report.html',
        report=report,
        format_currency=format_currency
    )

@app.route('/admin/reconciliation_report', methods=['GET'])
@login_required
@role_required('admin')
def reconciliation_report():
    reports = ReconciliationReport.query.order_by(ReconciliationReport.date.desc()).all()
    return render_template(
        'admin/reconciliation_report.html',
        reports=reports,
        format_currency=format_currency
    )

@app.route('/configure-report', methods=['GET', 'POST'])
@login_required
def configure_report():
    form = RecipientForm()

    if request.method == 'GET':
        last_notification = Notification.query.filter(
            Notification.email_recipients.isnot(None)
        ).order_by(Notification.timestamp.desc()).first()

        if last_notification:
            form.emails.data = last_notification.email_recipients
            form.subject.data = last_notification.email_subject

    if form.validate_on_submit():
        recipients = [email.strip() for email in form.emails.data.split(',')]
        success = send_sales_notification_email(
            recipients=recipients,
            custom_message=form.message.data,
            subject=form.subject.data
        )

        if success:
            flash('Report sent successfully!', 'success')
        else:
            flash('Failed to send report', 'danger')

        return redirect(url_for('configure_report'))

    return render_template('configure_report.html', form=form)


@app.route('/test-template')
def test_template():
    test_data = {
        'report_date': datetime.now().strftime("%B %d, %Y"),
        'today_sales': 1500000.50,
        'mtd_sales': 25000000.75,
        'total_budget': 30000000.00,
        'sales_pct': 83.3,
        'time_pct': 50.0,
        'working_days': 30,
        'days_passed': 15,
        'is_valid': True
    }
    return render_template('email/sales_report.html', **test_data)

import csv
from io import StringIO
from datetime import datetime
from flask import request, flash, redirect, url_for, render_template
from flask_login import login_required

def parse_csv_file(uploaded_file, expected_headers):
    """Read CSV file, validate headers, and return DictReader or error message."""
    if not uploaded_file or not uploaded_file.filename.endswith('.csv'):
        return None, "Upload a valid CSV file."

    stream = StringIO(uploaded_file.stream.read().decode('utf-8'), newline='')
    reader = csv.DictReader(stream)

    if not all(header in reader.fieldnames for header in expected_headers):
        return None, f"Invalid CSV headers. Expected: {', '.join(expected_headers)}"

    return reader, None


@app.route('/admin/upload_payroll', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def upload_payroll():
    """Bulk upload payroll deductions with duplicate detection."""
    if request.method == 'POST':
        reader, error = parse_csv_file(request.files.get('file'),
                                       ['loan_number', 'amount', 'deduction_date', 'vote_code'])
        if error:
            flash(error, 'danger')
            return redirect(url_for('upload_payroll'))

        batch_id = f"PAYROLL-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"
        processed, duplicates, errors = 0, 0, []

        for row in reader:
            try:
                loan = LoanApplication.query.filter_by(loan_number=row['loan_number']).first()
                if not loan:
                    errors.append(f"Loan {row['loan_number']} not found")
                    continue

                vote = Vote.query.filter_by(code=row['vote_code']).first()
                if not vote:
                    errors.append(f"Vote {row['vote_code']} not found")
                    continue

                deduction_date = datetime.strptime(row['deduction_date'], '%Y-%m-%d').date()
                amount = float(row['amount'])

                # Duplicate detection
                exists = PayrollDeduction.query.filter_by(
                    loan_id=loan.id,
                    vote_id=vote.id,
                    deduction_date=deduction_date,
                    amount=amount
                ).first()
                if exists:
                    duplicates += 1
                    continue

                schedule = RepaymentSchedule.query.filter_by(
                    loan_id=loan.id,
                    due_date=deduction_date
                ).first()

                deduction = PayrollDeduction(
                    loan_id=loan.id,
                    schedule_id=schedule.id if schedule else None,
                    vote_id=vote.id,
                    amount=amount,
                    deduction_date=deduction_date,
                    batch_id=batch_id,
                    status='processed'
                )
                db.session.add(deduction)
                processed += 1
            except Exception as e:
                errors.append(f"Error processing {row['loan_number']}: {str(e)}")

        try:
            db.session.commit()
            app.logger.info(f"Payroll batch {batch_id} processed: {processed} new, {duplicates} duplicates, {len(errors)} errors")
            flash(f'Processed: {processed} new, {duplicates} duplicates. Errors: {len(errors)}', 'success')
            if errors:
                flash("; ".join(errors), 'warning')
        except Exception as e:
            db.session.rollback()
            flash(f'Failed to process payroll batch: {str(e)}', 'danger')

        return redirect(url_for('upload_payroll'))

    return render_template('admin/upload_payroll_batch.html')


@app.route('/admin/upload_cash', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def upload_cash():
    """Bulk upload cash receipts with duplicate detection."""
    if request.method == 'POST':
        reader, error = parse_csv_file(request.files.get('file'),
                                       ['vote_code', 'amount', 'receipt_date', 'reference'])
        if error:
            flash(error, 'danger')
            return redirect(url_for('upload_cash'))

        batch_id = f"CASH-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"
        processed, duplicates, errors = 0, 0, []

        for row in reader:
            try:
                vote = Vote.query.filter_by(code=row['vote_code']).first()
                if not vote:
                    errors.append(f"Vote {row['vote_code']} not found")
                    continue

                receipt_date = datetime.strptime(row['receipt_date'], '%Y-%m-%d').date()
                amount = float(row['amount'])
                reference = row.get('reference', '').strip()

                # Duplicate detection
                exists = CashReceipt.query.filter_by(
                    vote_id=vote.id,
                    receipt_date=receipt_date,
                    amount=amount,
                    reference=reference
                ).first()
                if exists:
                    duplicates += 1
                    continue

                receipt = CashReceipt(
                    vote_id=vote.id,
                    amount=amount,
                    receipt_date=receipt_date,
                    reference=reference,
                    batch_id=batch_id,
                    status='processed'
                )
                db.session.add(receipt)
                processed += 1
            except Exception as e:
                errors.append(f"Error processing vote {row['vote_code']}: {str(e)}")

        try:
            db.session.commit()
            app.logger.info(f"Cash batch {batch_id} processed: {processed} new, {duplicates} duplicates, {len(errors)} errors")
            flash(f'Processed: {processed} new, {duplicates} duplicates. Errors: {len(errors)}', 'success')
            if errors:
                flash("; ".join(errors), 'warning')
        except Exception as e:
            db.session.rollback()
            flash(f'Failed to process cash batch: {str(e)}', 'danger')

        return redirect(url_for('upload_cash'))

    return render_template('admin/upload_cash_batch.html')

import json
from datetime import date, datetime
from app import app, db


def _get_month_range(month_str=None):
    """Helper to get month start and end dates."""
    if month_str:
        month_date = datetime.strptime(month_str, "%Y-%m").date()
    else:
        month_date = date.today().replace(day=1)

    month_start = month_date
    # Next month first day minus one day = last day of month
    if month_start.month == 12:
        month_end = date(month_start.year + 1, 1, 1) - timedelta(days=1)
    else:
        month_end = date(month_start.year, month_start.month + 1, 1) - timedelta(days=1)

    return month_start, month_end


def reconcile_cash(month_str=None):
    """
    Reconcile payroll deductions against cash receipts by vote for the given month.
    If month_str is None, uses current month.
    """
    with app.app_context():
        month_start, month_end = _get_month_range(month_str)

        discrepancies = []
        total_expected = 0
        total_received = 0

        for vote in Vote.query.all():
            deductions = PayrollDeduction.query.filter(
                PayrollDeduction.vote_id == vote.id,
                PayrollDeduction.deduction_date >= month_start,
                PayrollDeduction.deduction_date <= month_end
            ).all()

            receipts = CashReceipt.query.filter(
                CashReceipt.vote_id == vote.id,
                CashReceipt.receipt_date >= month_start,
                CashReceipt.receipt_date <= month_end
            ).all()

            deducted_sum = sum(d.amount for d in deductions)
            received_sum = sum(r.amount for r in receipts)

            total_expected += deducted_sum
            total_received += received_sum

            if abs(deducted_sum - received_sum) > 0.01:
                discrepancy_amount = deducted_sum - received_sum
                discrepancies.append({
                    'vote_code': vote.code,
                    'total_deducted': float(deducted_sum),
                    'total_received': float(received_sum),
                    'discrepancy': float(discrepancy_amount)
                })
                app.logger.warning(
                    f"[Vote {vote.code}] Cash discrepancy: "
                    f"Deducted {deducted_sum:.2f}, Received {received_sum:.2f}"
                )

        try:
            report = ReconciliationReport(
                date=month_end,
                level='cash',
                total_expected=total_expected,
                total_received=total_received,
                discrepancy_count=len(discrepancies),
                details=json.dumps(discrepancies)
            )
            db.session.add(report)
            db.session.commit()
            app.logger.info(f"Cash Reconciliation ({month_start} to {month_end}): Discrepancies: {len(discrepancies)}")
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Cash reconciliation failed: {str(e)}")


def reconcile_payroll(month_str=None):
    """
    Reconcile expected deductions from RepaymentSchedule against actual payroll deductions for the given month.
    If month_str is None, uses current month.
    """
    with app.app_context():
        month_start, month_end = _get_month_range(month_str)

        schedules = RepaymentSchedule.query.filter(
            RepaymentSchedule.due_date >= month_start,
            RepaymentSchedule.due_date <= month_end,
            RepaymentSchedule.status.notin_(['paid', 'settled', 'cancelled'])
        ).all()

        discrepancies = []
        total_expected = 0
        total_deducted = 0

        for schedule in schedules:
            expected_amount = float(schedule.expected_amount)
            total_expected += expected_amount

            deduction = PayrollDeduction.query.filter_by(
                schedule_id=schedule.id,
                deduction_date=schedule.due_date
            ).first()

            deducted_amount = float(deduction.amount) if deduction else 0.0
            total_deducted += deducted_amount

            if abs(expected_amount - deducted_amount) > 0.01:
                arrears_amount = expected_amount - deducted_amount

                if arrears_amount > 0:
                    existing = Arrear.query.filter_by(schedule_id=schedule.id).first()
                    if not existing:
                        arrear = Arrear(
                            loan_id=schedule.loan_id,
                            schedule_id=schedule.id,
                            due_date=schedule.due_date,
                            expected_amount=expected_amount,
                            deducted_amount=deducted_amount,
                            status='unresolved'
                        )
                        db.session.add(arrear)
                        app.logger.info(f"[{schedule.loan.loan_number}] Recorded arrear: {arrears_amount:.2f}")

                discrepancies.append({
                    'loan_number': schedule.loan.loan_number,
                    'schedule_id': schedule.id,
                    'due_date': str(schedule.due_date),
                    'expected': expected_amount,
                    'deducted': deducted_amount,
                    'arrears': arrears_amount
                })
                app.logger.warning(
                    f"[{schedule.loan.loan_number}] Payroll discrepancy in schedule {schedule.id}: "
                    f"Expected {expected_amount:.2f}, Deducted {deducted_amount:.2f}"
                )

        try:
            db.session.commit()
            app.logger.info(
                f"Payroll Reconciliation ({month_start} to {month_end}): "
                f"Expected: {total_expected:.2f}, Deducted: {total_deducted:.2f}, "
                f"Discrepancies: {len(discrepancies)}"
            )
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Payroll reconciliation failed: {str(e)}")

def format_mwk(amount):
    """Format amount as Malawian Kwacha"""
    return f"MWK {amount:,.2f}"

def check_db_schema():
    """Database schema validation function"""
    try:
        # FIXED: Imported inspect from sqlalchemy
        inspector = inspect(db.engine)
        cols = [c['name'] for c in inspector.get_columns('notifications')]
        
        required_columns = {
            'email_recipients', 'email_subject', 
            'email_content', 'email_sent', 'sent_at'
        }
        
        missing = required_columns - set(cols)
        if missing:
            current_app.logger.critical(f"Missing notification columns: {', '.join(missing)}")
            return False
        
        return True
    except Exception as e:
        current_app.logger.error(f"Schema validation failed: {str(e)}")
        return False

# Call during application startup   
# Usage example:
# sales_data['formatted_total'] = format_mwk(sales_data['total_budget'])
def auto_post_payments():
    print("🔥 auto_post_payments called")
    """
    Process automatic payments for due and backdated repayment schedules.
    Runs within app context to ensure database access.
    """
    with app.app_context():
        today = date.today()
        logger = logging.getLogger('auto_post')

        logger.info(json.dumps({
            'event': 'auto_post_start',
            'date': str(today),
            'timestamp': str(datetime.now())
        }))

        try:
            # Fetch schedules that are not paid, settled or cancelled and are due today or earlier
            schedules = RepaymentSchedule.query.filter(
                and_(
                    RepaymentSchedule.status.notin_(['paid', 'settled', 'cancelled']),
                    RepaymentSchedule.due_date <= today
                )
            ).order_by(RepaymentSchedule.due_date.asc()).all()

            logger.info(json.dumps({
                'event': 'schedules_fetched',
                'count': len(schedules),
                'schedule_ids': [s.id for s in schedules],
                'due_dates': [str(s.due_date) for s in schedules]
            }))

        except Exception as e:
            logger.error(json.dumps({
                'event': 'fetch_schedules_error',
                'error': str(e)
            }))
            return

        posted_count = 0
        backdated_count = 0
        batch_size = 50

        for i, sched in enumerate(schedules, 1):
            try:
                # Skip if due amount is zero or negative
                if sched.due_amount <= 0:
                    logger.info(json.dumps({
                        'event': 'skip_schedule',
                        'schedule_id': sched.id,
                        'reason': 'zero_due_amount',
                        'due_amount': sched.due_amount
                    }))
                    continue

                loan = sched.loan
                # Skip if no linked loan
                if not loan:
                    logger.info(json.dumps({
                        'event': 'skip_schedule',
                        'schedule_id': sched.id,
                        'reason': 'no_linked_loan'
                    }))
                    continue

                # Skip if loan state is not active
                if (loan.loan_state or "").strip().lower() != 'active':
                    logger.info(json.dumps({
                        'event': 'skip_loan',
                        'loan_number': loan.loan_number,
                        'reason': 'not_active',
                        'state': loan.loan_state
                    }))
                    continue

                # Skip if payment already exists for this schedule and date
                existing_payment = Payment.query.filter_by(reference=f"AUTO-{sched.id}-{today}").first()
                if existing_payment:
                    logger.info(json.dumps({
                        'event': 'skip_schedule',
                        'schedule_id': sched.id,
                        'reason': 'payment_exists'
                    }))
                    continue

                # Create payment record
                payment = Payment(
                    loan_id=loan.id,
                    amount=sched.due_amount,
                    method='auto_posted',
                    status='successful',
                    reference=f"AUTO-{sched.id}-{today}"
                )
                db.session.add(payment)

                # Allocate payment to loan
                loan.allocate_payment(payment)

                posted_count += 1

                # Log backdated payments
                if sched.due_date < today:
                    backdated_count += 1
                    days_overdue = (today - sched.due_date).days
                    logger.info(json.dumps({
                        'event': 'backdated_payment',
                        'schedule_id': sched.id,
                        'days_overdue': days_overdue,
                        'amount': sched.due_amount
                    }))

                logger.info(json.dumps({
                    'event': 'payment_posted',
                    'loan_number': loan.loan_number,
                    'schedule_id': sched.id,
                    'instalment_no': sched.instalment_no,
                    'amount': sched.due_amount
                }))

                # Commit every batch_size records
                if i % batch_size == 0:
                    db.session.commit()
                    logger.info(json.dumps({
                        'event': 'batch_commit',
                        'count': i
                    }))

            except Exception as e:
                logger.error(json.dumps({
                    'event': 'schedule_processing_error',
                    'schedule_id': sched.id,
                    'error': str(e)
                }))
                db.session.rollback()

        # Final commit after processing all schedules
        try:
            db.session.commit()
            logger.info(json.dumps({
                'event': 'auto_post_complete',
                'posted_count': posted_count,
                'backdated_count': backdated_count
            }))
        except Exception as e:
            logger.error(json.dumps({
                'event': 'commit_error',
                'error': str(e)
            }))
            db.session.rollback()

from flask import jsonify, request, render_template
from datetime import datetime, date
from sqlalchemy import extract
import threading
import os
from twilio.rest import Client

# SMS Sender with Rate Limiting
def send_sms(phone_number, message):
    """Send SMS with Twilio with cost controls"""
    # Skip if not a valid Malawi number
    if not phone_number.startswith('+265'):
        return False
    
    # Initialize Twilio client
    account_sid = os.environ.get('TWILIO_ACCOUNT_SID')
    auth_token = os.environ.get('TWILIO_AUTH_TOKEN')
    twilio_number = os.environ.get('TWILIO_PHONE_NUMBER')
    
    if not all([account_sid, auth_token, twilio_number]):
        print("Twilio credentials not configured")
        return False
    
    try:
        client = Client(account_sid, auth_token)
        message = client.messages.create(
            body=message,
            from_=twilio_number,
            to=phone_number
        )
        print(f"Sent SMS to {phone_number} (SID: {message.sid})")
        return True
    except Exception as e:
        print(f"Failed to send SMS to {phone_number}: {str(e)}")
        return False

@app.route("/send-birthday-sms", methods=["POST"])
def send_birthday_sms():
    # Get budget from request or use default
    max_messages = int(request.form.get('max_messages', 10))
    
    # Get today's month and day
    today = date.today()
    month = today.month
    day = today.day
    
    # Find customers with birthdays today
    customers = Customer.query.filter(
        extract('month', Customer.dob) == month,
        extract('day', Customer.dob) == day,
        Customer.phone.startswith('+265')  # Only Malawi numbers
    ).limit(max_messages).all()  # Limit to stay within budget
    
    if not customers:
        return jsonify({
            "success": True,
            "message": "No birthdays today",
            "count": 0
        })
    
    # Send SMS to each customer
    success_count = 0
    for customer in customers:
        message = (f"Happy Birthday {customer.first_name}! "
                   "Thank you for being our valued customer. "
                   "Wishing you a wonderful day!")
        
        if send_sms(customer.phone, message):
            success_count += 1
    
    # Calculate cost (approx $0.01 per SMS)
    estimated_cost = success_count * 0.01
    
    return jsonify({
        "success": True,
        "message": f"Sent {success_count}/{len(customers)} messages",
        "count": success_count,
        "estimated_cost": f"${estimated_cost:.2f}",
        "max_messages": max_messages
    })

@app.route("/sms-dashboard")
def sms_dashboard():
    # Get today's birthdays
    today = date.today()
    today_birthdays = Customer.query.filter(
        extract('month', Customer.dob) == today.month,
        extract('day', Customer.dob) == today.day
    ).all()
    
    return render_template(
        "sms_dashboard.html",
        today_birthdays=today_birthdays,
        last_sent=datetime.now().strftime("%Y-%m-%d %H:%M"),
        active_tab='sms'
    )

# Scheduled task (runs daily at 9AM)
def birthday_sms_scheduler():
    while True:
        now = datetime.now()
        # Run at 9:00 AM daily
        if now.hour == 9 and now.minute == 0:
            with app.app_context():
                # Create mock request to limit to 5 messages/day
                with app.test_request_context(
                    '/send-birthday-sms',
                    method='POST',
                    data={'max_messages': 5}
                ):
                    send_birthday_sms()
        time.sleep(60)

@app.route('/test-email-now')
def test_email_now():
    if send_sales_notification_email():
        return "Email sent successfully - check console and inbox!", 200
    return "Failed to send email", 500

def my_job():
    with app.app_context():
        print(f"[{datetime.now()}] Job executed")
        current_app.logger.info("Job executed")


def configure_scheduler():
    """Configure scheduler based on environment"""
    if app.config.get('TESTING'):
        return  # No scheduler jobs in tests

    env = os.environ.get('FLASK_ENV', 'development')

    if env == 'production':
        # Production - daily at 5PM
        scheduler.add_job(
            id='daily_sales_report',
            func=send_sales_notification_email,
            trigger='cron',
            hour=17,
            minute=0,
            replace_existing=True
        )
    else:
        # Development - every minute with initial 10s delay
        scheduler.add_job(
            id='dev_sales_notifications',
            func=send_sales_notification_email,
            trigger='interval',
            minutes=1,
            next_run_time=datetime.now() + timedelta(seconds=10),
            replace_existing=True
        )


def start_scheduler():
    """Start the scheduler with proper checks"""
    if not scheduler.running:
        configure_scheduler()
        scheduler.start()
        env = os.environ.get('FLASK_ENV', 'development')
        print(f"⏰ Scheduler started in {env} mode - Jobs: {[job.id for job in scheduler.get_jobs()]}")


scheduler.add_job(
    id='auto_post_due_schedules',
    func=auto_post_payments,
    trigger='cron',
    day=25,
    hour=0,
    minute=0,
    timezone='Africa/Blantyre',
    replace_existing=True
)

scheduler.add_job(
        id='sales_report',
        func=send_sales_notification_email,
        trigger='cron',
        hour=17,
        minute=0,
        timezone='Africa/Blantyre',
        max_instances=1,
        replace_existing=True
    )
    

def initialize_application():
    with app.app_context():
        # Your db setup, roles, etc.
        deploy()
        initialize_roles_permissions()

        # Print routes for debug
        for rule in app.url_map.iter_rules():
            print(f"{rule.endpoint} | {','.join(rule.methods - {'HEAD', 'OPTIONS'})} | {rule.rule}")

        return True

def register_jobs():
    scheduler.add_job(
        id='par_calculation',
        func=calculate_par,
        trigger='cron',
        hour=23,
        minute=0,
        timezone='Africa/Blantyre',
        replace_existing=True
    )
    
    

if __name__ == '__main__':
    scheduler.init_app(app)
    
    # Register environment-specific jobs
    configure_scheduler()  
    
    # Add any other always-needed jobs
    register_jobs()
    print(f"Jobs registered before start: {[job.id for job in scheduler.get_jobs()]}")
    scheduler.start()
    
    print(f"Scheduler started with jobs: {[job.id for job in scheduler.get_jobs()]}")
    
    if initialize_application():
        app.run(
            host=os.environ.get('FLASK_HOST', '0.0.0.0'),
            port=int(os.environ.get('FLASK_PORT', 5000)),
            debug=os.environ.get('FLASK_ENV') == 'development',
            use_reloader=False
        )
