"""
Database models for SecurePass using SQLAlchemy ORM
"""

from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()

class User(UserMixin, db.Model):
    """
    User model for authentication and authorization
    Implements Flask-Login UserMixin for session management
    """
    __tablename__ = 'users'
    
    user_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(50), unique=True, nullable=False, index=True)
    email = db.Column(db.String(100), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(10), default='user', nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    credentials = db.relationship('Credential', backref='owner', lazy='dynamic', cascade='all, delete-orphan')
    audit_logs = db.relationship('AuditLog', backref='user', lazy='dynamic', cascade='all, delete-orphan')
    
    def get_id(self):
        """Required by Flask-Login"""
        return str(self.user_id)
    
    def set_password(self, password):
        """Hash and set user password using bcrypt"""
        # FIX: Removed the 'method' argument. Werkzeug 3.0+ handles this automatically.
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        """Verify password against stored hash"""
        return check_password_hash(self.password_hash, password)
    
    def is_admin(self):
        """Check if user has admin role"""
        return self.role == 'admin'
    
    def __repr__(self):
        return f'<User {self.username}>'


class Credential(db.Model):
    """
    Credential model for storing encrypted passwords
    Each credential belongs to a user
    """
    __tablename__ = 'credentials'
    
    credential_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=False, index=True)
    website_name = db.Column(db.String(100), nullable=False, index=True)
    website_url = db.Column(db.String(255))
    username = db.Column(db.String(100), nullable=False)
    encrypted_password = db.Column(db.LargeBinary, nullable=False)  # Stores AES encrypted password
    notes = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def __repr__(self):
        return f'<Credential {self.website_name} for user {self.user_id}>'


class AuditLog(db.Model):
    """
    Audit log model for tracking user actions
    Used for security monitoring and compliance
    """
    __tablename__ = 'audit_logs'
    
    log_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=False, index=True)
    action = db.Column(db.String(50), nullable=False, index=True)
    description = db.Column(db.Text)
    ip_address = db.Column(db.String(45))  # IPv6 compatible
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    
    # Action types (constants)
    ACTION_LOGIN = 'LOGIN'
    ACTION_LOGOUT = 'LOGOUT'
    ACTION_REGISTER = 'REGISTER'
    ACTION_ADD_CREDENTIAL = 'ADD_CREDENTIAL'
    ACTION_VIEW_CREDENTIAL = 'VIEW_CREDENTIAL'
    ACTION_UPDATE_CREDENTIAL = 'UPDATE_CREDENTIAL'
    ACTION_DELETE_CREDENTIAL = 'DELETE_CREDENTIAL'
    ACTION_FAILED_LOGIN = 'FAILED_LOGIN'
    
    @staticmethod
    def log_action(user_id, action, description, ip_address=None):
        """
        Convenience method to create audit log entries
        
        Args:
            user_id: ID of user performing action
            action: Action type (use ACTION_* constants)
            description: Description of the action
            ip_address: IP address of user (optional)
        """
        log = AuditLog(
            user_id=user_id,
            action=action,
            description=description,
            ip_address=ip_address
        )
        db.session.add(log)
        db.session.commit()
    
    def __repr__(self):
        return f'<AuditLog {self.action} by user {self.user_id} at {self.timestamp}>'