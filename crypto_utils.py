"""
Cryptographic utilities for SecurePass
Uses AES-256-GCM for password encryption with PBKDF2 key derivation
"""

import os
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

# Master key (In production, store this in environment variable or secrets manager)
MASTER_PASSWORD = os.environ.get('MASTER_PASSWORD', 'your-super-secret-master-key-change-this')

def derive_key(master_password: str, salt: bytes) -> bytes:
    """
    Derive a 256-bit encryption key from master password using PBKDF2
    
    Args:
        master_password: The master password string
        salt: Random salt for key derivation
    
    Returns:
        32-byte AES key
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # 256 bits for AES-256
        salt=salt,
        iterations=100000,  # OWASP recommended minimum
        backend=default_backend()
    )
    return kdf.derive(master_password.encode())

def encrypt_password(plain_password: str) -> bytes:
    """
    Encrypt a password using AES-256-GCM
    
    Args:
        plain_password: The password to encrypt
    
    Returns:
        Encrypted data (salt + nonce + ciphertext + tag)
    """
    # Generate random salt and nonce
    salt = os.urandom(16)  # 128-bit salt
    nonce = os.urandom(12)  # 96-bit nonce for GCM
    
    # Derive encryption key
    key = derive_key(MASTER_PASSWORD, salt)
    
    # Create cipher and encrypt
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plain_password.encode(), None)
    
    # Combine salt + nonce + ciphertext for storage
    # Format: [16 bytes salt][12 bytes nonce][remaining bytes: ciphertext+tag]
    encrypted_data = salt + nonce + ciphertext
    
    return encrypted_data

def decrypt_password(encrypted_data: bytes) -> str:
    """
    Decrypt a password using AES-256-GCM
    
    Args:
        encrypted_data: The encrypted password data
    
    Returns:
        Decrypted password as string
    """
    try:
        # Extract components
        salt = encrypted_data[:16]
        nonce = encrypted_data[16:28]
        ciphertext = encrypted_data[28:]
        
        # Derive decryption key
        key = derive_key(MASTER_PASSWORD, salt)
        
        # Create cipher and decrypt
        aesgcm = AESGCM(key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        
        return plaintext.decode()
    except Exception as e:
        raise ValueError(f"Decryption failed: {str(e)}")

def generate_strong_password(length: int = 16) -> str:
    """
    Generate a cryptographically strong random password
    
    Args:
        length: Length of password (default 16)
    
    Returns:
        Random password string
    """
    import string
    import secrets
    
    # Character set for password
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
    
    # Ensure at least one of each type
    password = [
        secrets.choice(string.ascii_lowercase),
        secrets.choice(string.ascii_uppercase),
        secrets.choice(string.digits),
        secrets.choice("!@#$%^&*")
    ]
    
    # Fill rest with random characters
    password += [secrets.choice(alphabet) for _ in range(length - 4)]
    
    # Shuffle to randomize positions
    secrets.SystemRandom().shuffle(password)
    
    return ''.join(password)

# Test function
if __name__ == "__main__":
    # Test encryption/decryption
    test_password = "MySecretPass123!"
    print(f"Original: {test_password}")
    
    encrypted = encrypt_password(test_password)
    print(f"Encrypted (hex): {encrypted.hex()}")
    
    decrypted = decrypt_password(encrypted)
    print(f"Decrypted: {decrypted}")
    
    assert test_password == decrypted, "Encryption/Decryption test failed!"
    print("✓ Encryption test passed!")
    
    # Test password generation
    strong_pwd = generate_strong_password()
    print(f"\nGenerated strong password: {strong_pwd}")