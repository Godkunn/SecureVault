import sqlite3, os
from hashlib import scrypt
from database import get_db_connection

STATIC_SALT_FOR_KEY_DERIVATION = b'secure_vault_super_secret_key_derivation_salt_1234567890ABCDEF1234567890ABCDEF'

# Scrypt parameters for password hashing and key derivation
SCRYPT_N = 2**14 # CPU/Memory cost
SCRYPT_R = 8    # Block size
SCRYPT_P = 1    # Parallelization factor
SCRYPT_DKLEN = 32 # Derived key length in bytes (for AES-256)

def hash_password(password, salt=None):
    """
    Hashes a password using scrypt. Generates a new salt if not provided.
    Returns salt + hashed_password bytes.
    """
    if salt is None:
        salt = os.urandom(16) # Unique salt for each password hash
    hashed_password = scrypt(password.encode('utf-8'), salt=salt, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P, dklen=SCRYPT_DKLEN)
    return salt + hashed_password

def verify_password(stored_password_hash_with_salt, provided_password):
    """
    Verifies a provided password against a stored hash (which includes the salt).
    """
    if not stored_password_hash_with_salt or len(stored_password_hash_with_salt) < 16 + SCRYPT_DKLEN:
        return False # Invalid stored hash format
    
    salt = stored_password_hash_with_salt[:16]
    stored_hashed_password = stored_password_hash_with_salt[16:]
    
    rehashed_password = scrypt(provided_password.encode('utf-8'), salt=salt, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P, dklen=SCRYPT_DKLEN)
    return rehashed_password == stored_hashed_password

def derive_encryption_key_from_password(password):
    """
    Derives a consistent encryption key (pass_key) from the user's password
    using a static salt for reproducibility for a given user.
    """
    return scrypt(password.encode('utf-8'), salt=STATIC_SALT_FOR_KEY_DERIVATION, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P, dklen=SCRYPT_DKLEN)

def register_user(username, password):
    """Registers a new user in the database."""
    conn = get_db_connection()
    try:
        if conn.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone():
            print(f"Username '{username}' already exists.")
            return False
        
        hashed_pass_with_salt = hash_password(password)
        conn.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (username, hashed_pass_with_salt))
        conn.commit()
        print(f"User '{username}' registered successfully.")
        return True
    except sqlite3.Error as e:
        print(f"Database error during registration: {e}")
        return False
    finally:
        conn.close()

def login_user(username, password):
    """Authenticates a user and returns user info including the derived pass_key."""
    conn = get_db_connection()
    try:
        user_data = conn.execute("SELECT id, username, password_hash FROM users WHERE username = ?", (username,)).fetchone()
        if user_data:
            user_id, db_username, stored_password_hash_with_salt = user_data['id'], user_data['username'], user_data['password_hash']
            if verify_password(stored_password_hash_with_salt, password):
                # Derive the encryption key (pass_key) using the *same password* and static salt
                pass_key = derive_encryption_key_from_password(password)
                print(f"User '{username}' logged in successfully. Key derived.")
                return {'id': user_id, 'username': db_username, 'pass_key': pass_key}
            else:
                print(f"Login failed for '{username}': Password mismatch.")
        else:
            print(f"Login failed for '{username}': User not found.")
        return None
    except sqlite3.Error as e:
        print(f"Database error during login: {e}")
        return None
    finally:
        conn.close()