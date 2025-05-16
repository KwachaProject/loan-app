from flask import Flask, render_template, request, redirect, url_for, flash, send_file, jsonify 
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

# Initialize the Flask application
app = Flask(__name__)
app.secret_key = 'supersecretkey'

# Configure the app to use a SQLite database
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///customers.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'youremail@example.com'
app.config['MAIL_PASSWORD'] = 'your_app_password'  # Use App Passwords if Gmail
app.config['MAIL_DEFAULT_SENDER'] = 'youremail@example.com'

mail = Mail(app)
import os

UPLOAD_FOLDER = 'uploads/documents'
MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16 MB max upload size
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'pdf', 'doc', 'docx'}

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'your-secret-key-123'  # Change this!
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH
# Initialize SQLAlchemy and Migrate instances
db = SQLAlchemy(app)
migrate = Migrate(app, db)

# Import models after initializing the db instance
from app import db

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
    username = db.Column(db.String(100), unique=True)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='loan_officer')  # Roles: admin, loan_officer, customer_support
    email = db.Column(db.String(150), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def __repr__(self):
        return f'<User {self.username} - Role: {self.role}>'
    
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
            if current_user.role not in roles:
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
    file_number = db.Column(db.String(20), unique=True, nullable=True)
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
    loan_amount = db.Column(db.Float)
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
    schedule_id = db.Column(db.Integer, db.ForeignKey('repayment_schedules.id', use_alter=True, name='fk_schedule_id'),
    nullable=True)
    loan_number = db.Column(db.String(20), nullable=True, unique=True)
    file_number = db.Column(db.String(20), nullable=True, unique=True)
    date_created = db.Column(db.DateTime, default=datetime.utcnow)
    disbursement_date = db.Column(db.Date, nullable=True)

    # Relationships
    payments = db.relationship('Payment', back_populates='loan', cascade='all, delete-orphan')
    customer = db.relationship('Customer', back_populates='loans') 
    repayment_schedules = db.relationship(
        'RepaymentSchedule',
        back_populates='loan',
        cascade='all, delete-orphan',
        foreign_keys='RepaymentSchedule.loan_id'
        )


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
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    
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
    # Ensure session is available and get the loan fresh from DB
    session = object_session(target)
    loan = session.query(LoanApplication).get(target.loan_id)  # Fetch loan directly 
    
    if not loan:
        raise ValueError(f"Loan not found for payment ID {target.id} with loan_id {target.loan_id}")

    allocate_payment(target, loan)


def allocate_payment(payment: Payment, loan: LoanApplication):
    if not loan:
        raise ValueError("Loan not found for payment allocation.")

    # Validate loan term
    if not loan.term_months:
        raise ValueError("Loan term (term_months) is not set.")
    
    # Fetch pricing config
    config = PRICING.get(loan.term_months)
    if not config:
        raise ValueError(f"No pricing config for term {loan.term_months} months")

    # Use 'rate' instead of 'interest'
    if 'rate' not in config:
        raise ValueError(f"Interest rate ('rate') missing for term {loan.term_months} months")

    monthly_interest_rate = config['rate']  # ← Key changed to 'rate'

    # Calculate fees from original requested/loaned amount
    requested = loan.loan_amount  # or use loan.requested_amount if defined

    monthly_interest_rate = config.get('interest', 0.0)  # Default to 0% if missing
    if monthly_interest_rate <= 0:
        app.logger.warning(f"No interest rate defined for term {loan.term_months} months")

    collection_fee = requested * config['collection']
    fees = min(collection_fee, payment.amount)
    remaining_after_fees = payment.amount - fees

    # Compute capitalized balance
    capitalized = (
        loan.loan_amount +
        (loan.loan_amount * config['origination']) +
        (loan.loan_amount * config['insurance']) +
        config['crb']
    )
    
    # Total paid principal so far
    paid_principal = sum(
        alloc.principal for p in loan.payments if p.allocation for alloc in [p.allocation]
    )
    remaining_principal = capitalized - paid_principal

    remaining_principal = capitalized - paid_principal

    monthly_interest_rate = config['rate']
    interest_due = remaining_principal * monthly_interest_rate
    interest = min(interest_due, remaining_after_fees)  # Deduct interest next
    remaining_after_interest = remaining_after_fees - interest

    principal = min(remaining_after_interest, remaining_principal)

    allocation = PaymentAllocation(
        payment_id=payment.id,
        principal=principal,
        interest=interest,
        fees=fees
    )

    session = object_session(payment)
    session.add(allocation)


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

    return loan

from sqlalchemy.orm import configure_mappers
configure_mappers()

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

# Route to view a document
from flask_mail import Message

def notify_ceo_loan_approved(customer_name, loan_amount):
    ceo = User.query.filter_by(role='ceo').first()
    if ceo:
        msg = Message("Loan Ready for CEO Approval", recipients=[ceo.email])
        msg.body = f"The loan for customer {customer_name} (amount: {loan_amount}) has been approved by the CFO and awaits your review."
        mail.send(msg)

@app.route('/approve_loan/<int:loan_id>', methods=['POST'])
@role_required("chief_operations", "admin")
def approve_loan(loan_id):
    loan = LoanApplication.query.get_or_404(loan_id)
    loan.status = 'Approved'
    db.session.commit()

    notify_ceo_loan_approved(loan.customer.name, loan.amount)
    flash('Loan approved and CEO notified.', 'success')
    return redirect(url_for('view_loans'))

# ---------------- Routes ----------------
@app.route('/users', methods=['GET', 'POST'])
@role_required("admin")
def manage_users():
    users = User.query.all()
    if request.method == 'POST':
        user_id = request.form.get('user_id')
        new_role = request.form.get('role')
        user = User.query.get(user_id)
        if user:
            user.role = new_role
            db.session.commit()
            flash(f"{user.username}'s role updated to {new_role}", "success")
        return redirect(url_for('manage_users'))

    return render_template('manage_users.html', users=users)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    
    if request.method == 'POST':
        username = request.form['username']  # Changed from email
        user = User.query.filter_by(username=username).first()
        password = request.form['password']
        
        
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('home'))
        flash('Invalid email or password', 'danger')
    return render_template('login.html')


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

    # Uniqueness checks
    if Customer.query.filter_by(email=data['email']).first():
        raise Exception("Email already exists.")
    if Customer.query.filter_by(national_id=data['national_id']).first():
        raise Exception("National ID already exists.")

    # Generate File Number
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
        next_of_kin_relationship = request.form.get("next_of_kin_relationship"),
        next_of_kin_contact = request.form.get("next_of_kin_contact"),
        next_of_kin_name = request.form.get('next_of_kin_name'),
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
        status='pending',
        crb_fees=crb_fees,
        origination_fees=round(origination_fees, 2),
        insurance_fees=round(insurance_fees, 2),
        collection_fees=round(collection_fees, 2)
    )

    db.session.add(loan)
    db.session.flush()  # This assigns an ID before committing

    loan.generate_repayment_schedule()

    db.session.commit()

@app.route('/customers')
def customers():
    approved_customers = Customer.query.filter_by(is_approved_for_creation=True).all()
    return render_template('customers_list.html', customers=approved_customers)

@app.route('/approve_customers', methods=['GET', 'POST'])
@role_required("credit_officer", "admin")
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
                        amount=customer.amount_requested,
                        loan_category="SME",
                        status='pending'
                    )
                    db.session.add(loan)
                else:
                    customer.loans.status = 'pending'
            db.session.commit()
            flash(f"{len(customers)} customer(s) approved!", "success")
        else:
            flash("No customers selected.", "warning")
        return redirect(url_for('approve_customers'))

    unapproved_customers = Customer.query.filter_by(is_approved_for_creation=False).all()
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
    if action in ['approve', 'reject']:
        loan.status = 'approved' if action == 'approve' else 'rejected'
        db.session.commit()
        flash(f'Loan {action}d successfully.', 'info')
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
@role_required("admin")
def approve_loans():
    if request.method == 'POST':
        loan_ids = request.form.getlist('loan_ids')
        if loan_ids:
            loans = LoanApplication.query.filter(LoanApplication.id.in_(loan_ids)).all()
            for loan in loans:
                loan.status = 'approved'  # ✅ Must match exactly
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

# -------- Disbursement Routes --------

@app.route('/disbursements', methods=['GET', 'POST'])
@role_required("admin")
def disbursements():
    if request.method == 'POST':
        selected_ids = request.form.getlist('loan_ids[]')
        selected_bank = request.form.get('bank')

        if not selected_bank:
            flash("Please select a bank.", "warning")
            return redirect(url_for('disbursements'))

        if selected_ids:
            loans_to_process = LoanApplication.query\
                .join(Customer)\
                .filter(LoanApplication.id.in_(selected_ids))\
                .filter(LoanApplication.status == 'approved')\
                .filter(LoanApplication.disbursed == False)\
                .filter(Customer.is_approved_for_creation == True)\
                .all()

            if loans_to_process:
                for loan in loans_to_process:
                    loan.disbursed = True
                    loan.disbursed_bank = selected_bank
                    loan.disbursement_date = datetime.utcnow().date()
                    loan.generate_repayment_schedule()

                db.session.commit()
                return generate_disbursement_letter(loans_to_process, selected_bank)
            else:
                flash("Selected loans are not eligible for disbursement.", "danger")
        else:
            flash("No loans selected for disbursement.", "warning")

        return redirect(url_for('disbursements'))

    # Show approved, undistributed loans only
    loans = LoanApplication.query\
        .join(Customer)\
        .filter(LoanApplication.status == 'approved')\
        .filter(LoanApplication.disbursed == False)\
        .filter(Customer.is_approved_for_creation == True)\
        .all()

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
        pdf.cell(col_widths['amount'], 8, f"{loan.loan_amount:,.2f}", border=1, ln=True)

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

@app.route('/loanbook')
def loanbook():
    try:
        # Get all loans with payment allocations in a single query
        loans = db.session.query(
            LoanApplication,
            Customer,
            func.coalesce(func.sum(PaymentAllocation.principal), 0).label('total_principal_paid')
        ).join(
            Customer, LoanApplication.customer_id == Customer.id
        ).outerjoin(
            Payment, LoanApplication.id == Payment.loan_id
        ).outerjoin(
            PaymentAllocation, Payment.id == PaymentAllocation.payment_id
        ).group_by(LoanApplication.id).all()

        processed_loans = []
        
        for loan, customer, total_principal_paid in loans:
            config = PRICING.get(loan.term_months or 0, {})
            loan_amount = loan.loan_amount or 0

            # Calculate capitalized amount once
            capitalized = (
                loan_amount 
                + (loan_amount * config.get('origination', 0))
                + (loan_amount * config.get('insurance', 0))
                + config.get('crb', 0)
            )

            # Calculate remaining balance using SQL aggregate result
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

        # ... rest of totals calculation ...
        # Totals (match your template)
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
            loans=processed_loans,
            loan_categories={loan['loan']['category'] for loan in processed_loans if loan['loan']['category']},
            loan_tenures=sorted({loan['loan']['term'] for loan in processed_loans if loan['loan']['term'] is not None}),
            totals=totals
        )

    except Exception as e:
        flash(f"Error loading loan book: {str(e)}", "danger")
        return redirect(url_for('home'))

@app.route('/loan/<loan_number>/statement')
def loan_statement(loan_number):
    try:
        # Get loan with all relationships
        loan = (LoanApplication.query
                .options(
                    db.joinedload(LoanApplication.customer),  # Using original relationship name
                    db.joinedload(LoanApplication.payments)
                        .joinedload(Payment.allocation)
                )
                .filter_by(loan_number=loan_number)
                .first_or_404())
        
        # Calculate capitalized amount (principal + fees)
        config = PRICING.get(loan.term_months or 0, {})
        loan_amount = loan.loan_amount or 0
        capitalized_amount = (loan_amount + 
                            (loan_amount * config.get('origination', 0)) +
                            (loan_amount * config.get('insurance', 0)) +
                            config.get('crb', 0))
        
        # Process payments with proper allocation
        statement = []
        running_balance = capitalized_amount
        
        
        for payment in sorted(loan.payments, key=lambda p: p.created_at):
            if not payment.allocation:
                continue
            
            allocation = payment.allocation
            running_balance -= allocation.principal

            # Calculate the total amount allocated to the payment
            allocated_total = (allocation.principal or 0) + (allocation.interest or 0) + (allocation.fees or 0)
            
            # Check if the allocation is valid (matches the payment amount)
            valid_allocation = abs(allocated_total - payment.amount) < 0.01  # Allow for rounding tolerance

            statement.append({
                'date': payment.created_at.strftime('%Y-%m-%d'),
                'total': payment.amount,
                'principal': allocation.principal,
                'interest': allocation.interest,
                'collection_fees': allocation.fees,
                'remaining_balance': running_balance,
                'method': payment.method,
                'reference': payment.reference,
                'valid_allocation': valid_allocation
            })
        
        # Get repayment schedule entries for the loan
            schedule_rows = (RepaymentSchedule.query
                            .filter_by(loan_id=loan.id)
                            .order_by(RepaymentSchedule.due_date)
                            .all())

            # Filter out paid rows
            sorted_schedule = sorted(schedule_rows, key=lambda r: r.due_date)

            # Count number of paid entries
            paid_count = sum(1 for row in sorted_schedule if row.status == 'paid')

            # Get next unpaid schedule entries
            next_3 = sorted_schedule[paid_count:paid_count + 3]
            next_6 = sorted_schedule[paid_count:paid_count + 6]

            # Sum interest from those rows
            top_up_interest = sum(row.expected_interest or 0 for row in next_3)
            settlement_interest = sum(row.expected_interest or 0 for row in next_6)

            # Compute balances
            top_up_balance = round(running_balance + top_up_interest, 2)
            settlement_balance = round(running_balance + settlement_interest, 2)



        # Totals for the loan statement
        totals = {
            'paid': sum(p.amount for p in loan.payments),
            'principal': sum(p.allocation.principal for p in loan.payments if p.allocation),
            'interest': sum(p.allocation.interest for p in loan.payments if p.allocation),
            'fees': sum(p.allocation.fees for p in loan.payments if p.allocation)
        }
        
        return render_template(
            'loan_statement.html',
            loan=loan,
            statement=statement,
            capitalized_amount=round(capitalized_amount, 2),
            current_balance=round(running_balance, 2),
            top_up_balance=round(top_up_balance, 2),
            settlement_balance=round(settlement_balance, 2),
            totals=totals  # ← this was missing
            
        )

    except Exception as e:
        flash(f"Error generating statement: {str(e)}", "danger")
        return redirect(url_for('loanbook'))

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

if __name__ == '__main__':
    app.run(debug=True)