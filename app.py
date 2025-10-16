"""
SecurePass - Secure Password Manager
Main Flask application with routes and business logic
"""

import os
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from models import db, User, Credential, AuditLog
from crypto_utils import encrypt_password, decrypt_password, generate_strong_password
from functools import wraps
from datetime import datetime

# Initialize Flask app
app = Flask(__name__)

# Configuration
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get(
    'DATABASE_URL',
    'sqlite:///securepass.db'
)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ECHO'] = False

# Initialize extensions
db.init_app(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access this page.'
login_manager.login_message_category = 'info'

# User loader for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    """Load user by ID for session management"""
    return db.session.get(User, int(user_id))

# Helper function to get client IP
def get_client_ip():
    """Get client IP address from request"""
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0]
    return request.remote_addr or '127.0.0.1'

# Admin required decorator
def admin_required(f):
    """Decorator to require admin role for route access"""
    @wraps(f)
    @login_required
    def decorated_function(*args, **kwargs):
        if not current_user.is_admin():
            flash('You need admin privileges to access this page.', 'danger')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

# ============================================
# AUTHENTICATION ROUTES
# ============================================

@app.route('/')
def index():
    """Landing page - redirect to dashboard if logged in"""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    """User registration"""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        
        # Validation
        if not username or not email or not password:
            flash('All fields are required.', 'danger')
            return render_template('register.html')
        
        if password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return render_template('register.html')
        
        if len(password) < 8:
            flash('Password must be at least 8 characters long.', 'danger')
            return render_template('register.html')
        
        # Check if user exists
        if User.query.filter_by(username=username).first():
            flash('Username already exists.', 'danger')
            return render_template('register.html')
        
        if User.query.filter_by(email=email).first():
            flash('Email already registered.', 'danger')
            return render_template('register.html')
        
        # Create new user
        try:
            user = User(username=username, email=email, role='user')
            user.set_password(password)
            
            db.session.add(user)
            db.session.commit()
            
            # Log registration
            try:
                log = AuditLog(
                    user_id=user.user_id,
                    action='REGISTER',
                    description=f'User {username} registered',
                    ip_address=get_client_ip()
                )
                db.session.add(log)
                db.session.commit()
            except:
                pass  # Don't fail registration if logging fails
            
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            flash('Registration failed. Please try again.', 'danger')
            print(f'Registration error: {str(e)}')
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """User login"""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        remember = bool(request.form.get('remember', False))
        
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            login_user(user, remember=remember)
            
            # Log successful login
            try:
                log = AuditLog(
                    user_id=user.user_id,
                    action='LOGIN',
                    description=f'User {username} logged in successfully',
                    ip_address=get_client_ip()
                )
                db.session.add(log)
                db.session.commit()
            except:
                pass
            
            flash(f'Welcome back, {user.username}!', 'success')
            
            # Redirect to next page or dashboard
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('dashboard'))
        else:
            # Log failed login attempt
            if user:
                try:
                    log = AuditLog(
                        user_id=user.user_id,
                        action='FAILED_LOGIN',
                        description=f'Failed login attempt for user {username}',
                        ip_address=get_client_ip()
                    )
                    db.session.add(log)
                    db.session.commit()
                except:
                    pass
            flash('Invalid username or password.', 'danger')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    """User logout"""
    # Log logout
    try:
        log = AuditLog(
            user_id=current_user.user_id,
            action='LOGOUT',
            description=f'User {current_user.username} logged out',
            ip_address=get_client_ip()
        )
        db.session.add(log)
        db.session.commit()
    except:
        pass
    
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

# ============================================
# CREDENTIAL MANAGEMENT ROUTES
# ============================================

@app.route('/dashboard')
@login_required
def dashboard():
    """User dashboard showing all credentials"""
    credentials = Credential.query.filter_by(user_id=current_user.user_id).order_by(
        Credential.updated_at.desc()
    ).all()
    
    return render_template('dashboard.html', credentials=credentials)

@app.route('/credential/add', methods=['GET', 'POST'])
@login_required
def add_credential():
    """Add new credential"""
    if request.method == 'POST':
        website_name = request.form.get('website_name', '').strip()
        website_url = request.form.get('website_url', '').strip()
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        notes = request.form.get('notes', '').strip()
        
        # Validation
        if not website_name or not username or not password:
            flash('Website name, username, and password are required.', 'danger')
            return render_template('add_credential.html')
        
        # Encrypt password
        try:
            encrypted_pwd = encrypt_password(password)
            
            # Create credential
            credential = Credential(
                user_id=current_user.user_id,
                website_name=website_name,
                website_url=website_url,
                username=username,
                encrypted_password=encrypted_pwd,
                notes=notes
            )
            
            db.session.add(credential)
            db.session.commit()
            
            # Log action
            try:
                log = AuditLog(
                    user_id=current_user.user_id,
                    action='ADD_CREDENTIAL',
                    description=f'Added credential for {website_name}',
                    ip_address=get_client_ip()
                )
                db.session.add(log)
                db.session.commit()
            except:
                pass
            
            flash('Credential saved successfully!', 'success')
            return redirect(url_for('dashboard'))
        except Exception as e:
            db.session.rollback()
            flash('Failed to save credential. Please try again.', 'danger')
            print(f'Add credential error: {str(e)}')
    
    return render_template('add_credential.html')

@app.route('/credential/view/<int:credential_id>')
@login_required
def view_credential(credential_id):
    """View and decrypt credential"""
    credential = db.session.get(Credential, credential_id)
    
    if not credential:
        flash('Credential not found.', 'danger')
        return redirect(url_for('dashboard'))
    
    # Authorization check
    if credential.user_id != current_user.user_id and not current_user.is_admin():
        flash('Unauthorized access.', 'danger')
        return redirect(url_for('dashboard'))
    
    try:
        # Decrypt password
        decrypted_password = decrypt_password(credential.encrypted_password)
        
        # Log action
        try:
            log = AuditLog(
                user_id=current_user.user_id,
                action='VIEW_CREDENTIAL',
                description=f'Viewed credential for {credential.website_name}',
                ip_address=get_client_ip()
            )
            db.session.add(log)
            db.session.commit()
        except:
            pass
        
        return render_template('view_credential.html', credential=credential, password=decrypted_password)
    except Exception as e:
        flash('Failed to decrypt password.', 'danger')
        print(f'Decrypt error: {str(e)}')
        return redirect(url_for('dashboard'))

@app.route('/credential/edit/<int:credential_id>', methods=['GET', 'POST'])
@login_required
def edit_credential(credential_id):
    """Edit existing credential"""
    credential = db.session.get(Credential, credential_id)
    
    if not credential:
        flash('Credential not found.', 'danger')
        return redirect(url_for('dashboard'))
    
    # Authorization check
    if credential.user_id != current_user.user_id:
        flash('Unauthorized access.', 'danger')
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        website_name = request.form.get('website_name', '').strip()
        website_url = request.form.get('website_url', '').strip()
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        notes = request.form.get('notes', '').strip()
        
        if not website_name or not username:
            flash('Website name and username are required.', 'danger')
            decrypted_password = ''
            try:
                decrypted_password = decrypt_password(credential.encrypted_password)
            except:
                pass
            return render_template('edit_credential.html', credential=credential, password=decrypted_password)
        
        try:
            credential.website_name = website_name
            credential.website_url = website_url
            credential.username = username
            credential.notes = notes
            
            # Update password if provided
            if password:
                credential.encrypted_password = encrypt_password(password)
            
            credential.updated_at = datetime.utcnow()
            db.session.commit()
            
            # Log action
            try:
                log = AuditLog(
                    user_id=current_user.user_id,
                    action='UPDATE_CREDENTIAL',
                    description=f'Updated credential for {website_name}',
                    ip_address=get_client_ip()
                )
                db.session.add(log)
                db.session.commit()
            except:
                pass
            
            flash('Credential updated successfully!', 'success')
            return redirect(url_for('dashboard'))
        except Exception as e:
            db.session.rollback()
            flash('Failed to update credential.', 'danger')
            print(f'Update credential error: {str(e)}')
    
    # Decrypt password for display
    decrypted_password = ''
    try:
        decrypted_password = decrypt_password(credential.encrypted_password)
    except:
        pass
    
    return render_template('edit_credential.html', credential=credential, password=decrypted_password)

@app.route('/credential/delete/<int:credential_id>', methods=['POST'])
@login_required
def delete_credential(credential_id):
    """Delete credential"""
    credential = db.session.get(Credential, credential_id)
    
    if not credential:
        flash('Credential not found.', 'danger')
        return redirect(url_for('dashboard'))
    
    # Authorization check
    if credential.user_id != current_user.user_id and not current_user.is_admin():
        flash('Unauthorized access.', 'danger')
        return redirect(url_for('dashboard'))
    
    try:
        website_name = credential.website_name
        db.session.delete(credential)
        db.session.commit()
        
        # Log action
        try:
            log = AuditLog(
                user_id=current_user.user_id,
                action='DELETE_CREDENTIAL',
                description=f'Deleted credential for {website_name}',
                ip_address=get_client_ip()
            )
            db.session.add(log)
            db.session.commit()
        except:
            pass
        
        flash('Credential deleted successfully.', 'success')
    except Exception as e:
        db.session.rollback()
        flash('Failed to delete credential.', 'danger')
        print(f'Delete credential error: {str(e)}')
    
    return redirect(url_for('dashboard'))

# ============================================
# ADMIN ROUTES
# ============================================

@app.route('/admin')
@admin_required
def admin_panel():
    """Admin dashboard with user and audit statistics"""
    total_users = User.query.count()
    total_credentials = Credential.query.count()
    recent_logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(20).all()
    all_users = User.query.order_by(User.created_at.desc()).all()
    
    return render_template('admin.html', 
                         total_users=total_users,
                         total_credentials=total_credentials,
                         recent_logs=recent_logs,
                         users=all_users)

# ============================================
# API ROUTES
# ============================================

@app.route('/api/generate-password')
@login_required
def api_generate_password():
    """API endpoint to generate strong password"""
    length = request.args.get('length', 16, type=int)
    length = max(8, min(length, 32))
    
    password = generate_strong_password(length)
    return jsonify({'password': password})

# ============================================
# ERROR HANDLERS
# ============================================

@app.errorhandler(404)
def not_found_error(error):
    """Handle 404 errors"""
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    """Handle 500 errors"""
    db.session.rollback()
    return render_template('500.html'), 500

# ============================================
# DATABASE INITIALIZATION
# ============================================

def init_database():
    """Initialize database and create tables"""
    with app.app_context():
        db.create_all()
        
        # Create default admin if not exists
        admin = User.query.filter_by(username='admin').first()
        if not admin:
            admin = User(username='admin', email='admin@securepass.com', role='admin')
            admin.set_password('Admin@123')
            db.session.add(admin)
            db.session.commit()
            print('✓ Admin user created! Username: admin, Password: Admin@123')
        else:
            print('✓ Admin user already exists')
        
        print('✓ Database initialized successfully!')

# ============================================
# MAIN
# ============================================

if __name__ == '__main__':
    init_database()
    port = int(os.environ.get('PORT', 5000))
    app.run(debug=False, host='0.0.0.0', port=port)
