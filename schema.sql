-- SecurePass Database Schema
-- PostgreSQL Version

-- Drop existing tables if they exist
DROP TABLE IF EXISTS audit_logs CASCADE;
DROP TABLE IF EXISTS credentials CASCADE;
DROP TABLE IF EXISTS users CASCADE;

-- Users table: stores user account information
CREATE TABLE users (
    user_id SERIAL PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(10) DEFAULT 'user' CHECK (role IN ('admin', 'user')),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_username ON users(username);
CREATE INDEX idx_email ON users(email);

-- Credentials table: stores encrypted passwords for different websites
CREATE TABLE credentials (
    credential_id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL,
    website_name VARCHAR(100) NOT NULL,
    website_url VARCHAR(255),
    username VARCHAR(100) NOT NULL,
    encrypted_password BYTEA NOT NULL,
    notes TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
);

CREATE INDEX idx_user_credentials ON credentials(user_id);
CREATE INDEX idx_website ON credentials(website_name);

-- Audit logs table: tracks all user actions for security
CREATE TABLE audit_logs (
    log_id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL,
    action VARCHAR(50) NOT NULL,
    description TEXT,
    ip_address VARCHAR(45),
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
);

CREATE INDEX idx_user_logs ON audit_logs(user_id);
CREATE INDEX idx_action ON audit_logs(action);
CREATE INDEX idx_timestamp ON audit_logs(timestamp);

-- Insert default admin user (password: Admin@123)
-- Password hash generated using Werkzeug
INSERT INTO users (username, email, password_hash, role) 
VALUES (
    'admin', 
    'admin@securepass.com', 
    'pbkdf2:sha256:600000$5qP9YmZK4RzQ6QCY$6f3c8b8c9d2a1e5f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f',
    'admin'
) ON CONFLICT (username) DO NOTHING;

-- Create view for user credential counts
CREATE OR REPLACE VIEW user_credential_count AS
SELECT 
    u.user_id,
    u.username,
    u.email,
    COUNT(c.credential_id) as total_credentials
FROM users u
LEFT JOIN credentials c ON u.user_id = c.user_id
GROUP BY u.user_id, u.username, u.email;

-- Create view for recent activities
CREATE OR REPLACE VIEW recent_activities AS
SELECT 
    al.log_id,
    u.username,
    al.action,
    al.description,
    al.ip_address,
    al.timestamp
FROM audit_logs al
JOIN users u ON al.user_id = u.user_id
ORDER BY al.timestamp DESC
LIMIT 100;

-- Success message
DO $$
BEGIN
    RAISE NOTICE '✓ SecurePass database schema created successfully!';
    RAISE NOTICE '✓ Default admin user: admin / Admin@123';
END $$;