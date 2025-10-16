"""
SecurePass - Automated Setup Script
Run this to initialize the database automatically
"""

from app import app, db
from models import User

def setup_database():
    """Create all tables and initialize data"""
    print("=" * 50)
    print("SecurePass Database Setup")
    print("=" * 50)
    
    with app.app_context():
        try:
            # Create all tables
            print("\n[1/3] Creating database tables...")
            db.create_all()
            print("✓ Tables created successfully!")
            
            # Create default admin user
            print("\n[2/3] Creating default admin user...")
            admin = User.query.filter_by(username='admin').first()
            
            if admin:
                print("ℹ Admin user already exists")
            else:
                admin = User(
                    username='admin',
                    email='admin@securepass.com',
                    role='admin'
                )
                admin.set_password('Admin@123')
                db.session.add(admin)
                db.session.commit()
                print("✓ Admin user created!")
                print("  Username: admin")
                print("  Password: Admin@123")
            
            print("\n[3/3] Verifying setup...")
            user_count = User.query.count()
            print(f"✓ Database has {user_count} user(s)")
            
            print("\n" + "=" * 50)
            print("✓ Setup completed successfully!")
            print("=" * 50)
            print("\nYou can now run the application:")
            print("  python app.py")
            print("\nThen visit: http://localhost:5000")
            print("\nDefault login:")
            print("  Username: admin")
            print("  Password: Admin@123")
            print("=" * 50)
            
        except Exception as e:
            print(f"\n✗ Error during setup: {str(e)}")
            print("\nPlease check:")
            print("  1. PostgreSQL/MySQL is running")
            print("  2. Database 'securepass' exists")
            print("  3. Database credentials in app.py are correct")
            return False
    
    return True

if __name__ == '__main__':
    setup_database()