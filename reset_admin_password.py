from app import app, db, User
from werkzeug.security import generate_password_hash

def reset_admin_password(username: str, new_password: str):
    with app.app_context():
        admin = User.query.filter_by(username=username).first()
        if admin:
            admin.password_hash = generate_password_hash(new_password)
            db.session.commit()
            print(f"✅ Password reset for user '{username}' successful.")
        else:
            print(f"❌ Admin user with username '{username}' not found.")

if __name__ == "__main__":
    # Change these values as needed
    admin_username = "admin"
    new_password = "securepassword123"

    reset_admin_password(admin_username, new_password)
