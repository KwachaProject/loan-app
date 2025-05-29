from app import db
from app import Customer, LoanApplication
from app import create_app  # Import your Flask app creation function

# Create an app instance
app = create_app()

# Ensure app context is active
with app.app_context():
    # Show available tables
    print("\nTables in database:")
    print("--------------------")
    inspector = db.inspect(db.engine)
    for table_name in inspector.get_table_names():
        print(f"- {table_name}")

    # Show Customer table structure
    print("\nCustomer Table Columns:")
    print("------------------------")
    for column in Customer.__table__.columns:
        print(f"{column.name} - {column.type}")

    # Show LoanApplication table structure
    print("\nLoanApplication Table Columns:")
    print("-------------------------------")
    for column in LoanApplication.__table__.columns:
        print(f"{column.name} - {column.type}")
