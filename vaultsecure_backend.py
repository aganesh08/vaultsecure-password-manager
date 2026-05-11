# vaultsecure_backend.py
import datetime
import sqlite3
import pyotp
import hashlib
import base64
import os
import secrets
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# --- AES256 Encryption Utilities ---
class AESCipher:
    def __init__(self, key):
        self.password = key.encode('utf-8')
        self.salt_size = 16
        self.nonce_size = 12
        self.iterations = 100000

    def _derive_key(self, salt):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=self.iterations,
        )
        return kdf.derive(self.password)

    def encrypt(self, raw):
        raw = raw.encode('utf-8')
        salt = os.urandom(self.salt_size)
        nonce = os.urandom(self.nonce_size)
        key = self._derive_key(salt)
        encrypted = AESGCM(key).encrypt(nonce, raw, None)
        return base64.b64encode(salt + nonce + encrypted).decode('utf-8')

    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        salt = enc[:self.salt_size]
        nonce = enc[self.salt_size:self.salt_size + self.nonce_size]
        encrypted = enc[self.salt_size + self.nonce_size:]
        key = self._derive_key(salt)
        decrypted = AESGCM(key).decrypt(nonce, encrypted, None)
        return decrypted.decode('utf-8')

# --- Secure Password Hashing with Salt ---
def hash_password_with_salt(password):
    """
    Hash password with a random salt using PBKDF2
    Returns: (salt, hashed_password) both as hex strings
    """
    # Generate a random salt (32 bytes = 256 bits)
    salt = secrets.token_bytes(32)
    
    # Use PBKDF2 with SHA-256, 100,000 iterations (industry standard)
    hashed = hashlib.pbkdf2_hmac(
        'sha256',           # Hash algorithm
        password.encode(),  # Password as bytes
        salt,              # Salt
        100000             # Number of iterations
    )
    
    # Return both salt and hash as hex strings for database storage
    return salt.hex(), hashed.hex()

def verify_password(password, stored_salt, stored_hash):
    """
    Verify a password against stored salt and hash
    """
    try:
        # Convert hex strings back to bytes
        salt = bytes.fromhex(stored_salt)
        
        # Hash the provided password with the stored salt
        hashed = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode(),
            salt,
            100000
        )
        
        # Compare with stored hash (convert stored hash from hex)
        return hashed.hex() == stored_hash
    
    except (ValueError, TypeError):
        # Handle invalid hex strings or other errors
        return False

def hash_password(password):
    """Simple hash function for password history (not for login passwords)"""
    return hashlib.sha256(password.encode()).hexdigest()

# --- MFA Utilities ---
def generate_mfa_secret():
    return pyotp.random_base32()

def get_totp(secret):
    return pyotp.TOTP(secret)

def verify_totp(secret, token):
    if not secret:
        return False  # MFA secret missing
    totp = pyotp.TOTP(secret)
    return totp.verify(token)

def get_mfa_secret(username):
    conn = sqlite3.connect('vaultsecure.db')
    c = conn.cursor()
    c.execute("SELECT mfa_secret FROM users WHERE username = ?", (username,))
    row = c.fetchone()
    conn.close()
    return row[0] if row else None

# --- Database Setup ---
def create_tables():
    conn = sqlite3.connect('vaultsecure.db')
    c = conn.cursor()
    
    # Create users table
    c.execute('''CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE,
                    password_hash TEXT,
                    password_salt TEXT,
                    mfa_secret TEXT,
                    timezone TEXT DEFAULT 'America/Los_Angeles'
                )''')
    
    # Check if salt column exists, add if not (for existing databases)
    c.execute("PRAGMA table_info(users)")
    columns = [column[1] for column in c.fetchall()]
    
    if 'password_salt' not in columns:
        print("Adding password_salt column to existing users table...")
        c.execute('ALTER TABLE users ADD COLUMN password_salt TEXT')
    
    # Check if timezone column exists, add if not
    if 'timezone' not in columns:
        print("Adding timezone column to existing users table...")
        c.execute('ALTER TABLE users ADD COLUMN timezone TEXT DEFAULT "America/Los_Angeles"')
    
    # Create vault table
    c.execute('''CREATE TABLE IF NOT EXISTS vault (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    service TEXT,
                    encrypted_password TEXT,
                    last_updated TEXT,
                    FOREIGN KEY(user_id) REFERENCES users(id)
                )''')
    
    # Create password history table
    c.execute('''CREATE TABLE IF NOT EXISTS password_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    service TEXT NOT NULL,
                    password_hash TEXT NOT NULL,
                    changed_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY(user_id) REFERENCES users(id)
                )''')
    
    # Create backups table
    c.execute('''CREATE TABLE IF NOT EXISTS backups (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    backup_time DATETIME DEFAULT CURRENT_TIMESTAMP,
                    backup_data BLOB NOT NULL,
                    FOREIGN KEY(user_id) REFERENCES users(id)
                )''')
    
    # Create activity log table
    c.execute('''CREATE TABLE IF NOT EXISTS activity_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    service TEXT NOT NULL,
                    action TEXT NOT NULL,  -- 'created', 'updated', 'deleted'
                    timestamp TEXT NOT NULL,
                    FOREIGN KEY(user_id) REFERENCES users(id)
                )''')
    
    conn.commit()
    conn.close()

# --- Activity Logging ---
def log_activity(user_id, service, action):
    now = datetime.datetime.utcnow().isoformat()
    conn = sqlite3.connect('vaultsecure.db')
    c = conn.cursor()
    c.execute("INSERT INTO activity_log (user_id, service, action, timestamp) VALUES (?, ?, ?, ?)",
              (user_id, service, action, now))
    conn.commit()
    conn.close()

# --- User Authentication ---
def user_exists(username):
    conn = sqlite3.connect('vaultsecure.db')
    c = conn.cursor()
    c.execute("SELECT 1 FROM users WHERE username = ?", (username,))
    exists = c.fetchone() is not None
    conn.close()
    return exists

def register_user(username, password):
    """Register a new user with salted password hashing"""
    try:
        conn = sqlite3.connect('vaultsecure.db')
        c = conn.cursor()
        
        # Check if user already exists
        c.execute("SELECT username FROM users WHERE username = ?", (username,))
        if c.fetchone():
            conn.close()
            return False, "Username already exists"
        
        # Validate password strength
        if len(password) < 8:
            conn.close()
            return False, "Password must be at least 8 characters long"
        
        # Hash password with salt
        salt, password_hash = hash_password_with_salt(password)
        
        # Generate MFA secret
        mfa_secret = generate_mfa_secret()
        
        # Store user with salt and hash
        c.execute("INSERT INTO users (username, password_hash, password_salt, mfa_secret) VALUES (?, ?, ?, ?)",
                  (username, password_hash, salt, mfa_secret))
        
        conn.commit()
        conn.close()
        
        return True, mfa_secret
    
    except sqlite3.IntegrityError:
        return False, "Username already exists"
    except Exception as e:
        return False, f"Registration failed: {str(e)}"

def authenticate_user(username, password):
    """Authenticate user with salted password verification"""
    try:
        conn = sqlite3.connect('vaultsecure.db')
        c = conn.cursor()
        
        # Get user data including salt
        c.execute("SELECT password_hash, password_salt, mfa_secret FROM users WHERE username = ?", (username,))
        result = c.fetchone()
        conn.close()
        
        if not result:
            # User doesn't exist - still do a dummy hash calculation to prevent timing attacks
            hash_password_with_salt("dummy_password")
            return False, "Invalid username or password"
        
        stored_hash, stored_salt, mfa_secret = result
        
        # Verify password using salt
        if verify_password(password, stored_salt, stored_hash):
            return True, mfa_secret
        else:
            return False, "Invalid username or password"
    
    except Exception as e:
        return False, f"Authentication failed: {str(e)}"

# --- Vault Operations ---
def normalize_service(service):
    return service.strip().lower()

def store_password(username, service, password, encryption_key):
    service = normalize_service(service)
    cipher = AESCipher(encryption_key)
    encrypted = cipher.encrypt(password)
    now = datetime.datetime.utcnow().isoformat()
    
    conn = sqlite3.connect('vaultsecure.db')
    c = conn.cursor()
    c.execute("SELECT id FROM users WHERE username = ?", (username,))
    user_id = c.fetchone()
    if not user_id:
        conn.close()
        return False, "User not found."
    user_id = user_id[0]
    
    # Check if service already exists for user
    c.execute("SELECT 1 FROM vault WHERE user_id = ? AND service = ?", (user_id, service))
    exists = c.fetchone()
    
    # Check password history before inserting
    if is_password_reused(user_id, service, password):
        conn.close()
        return False, "You cannot reuse your last 3 passwords for this service."
    
    c.execute("INSERT INTO vault (user_id, service, encrypted_password, last_updated) VALUES (?, ?, ?, ?)",
              (user_id, service, encrypted, now))
    conn.commit()
    conn.close()
    
    # Store the password in history
    store_password_history(user_id, service, password)
    
    # Log activity
    if exists:
        log_activity(user_id, service, "updated")
    else:
        log_activity(user_id, service, "created")
    
    # Backup after change
    backup_vault(user_id, encryption_key)
    return True, "Password added successfully."

def update_password(username, service, new_password, encryption_key):
    service = normalize_service(service)
    cipher = AESCipher(encryption_key)
    encrypted = cipher.encrypt(new_password)
    now = datetime.datetime.utcnow().isoformat()
    
    conn = sqlite3.connect('vaultsecure.db')
    c = conn.cursor()
    c.execute("SELECT id FROM users WHERE username = ?", (username,))
    user_id = c.fetchone()
    if not user_id:
        conn.close()
        return False, "User not found."
    user_id = user_id[0]
    
    # Check password history
    if is_password_reused(user_id, service, new_password):
        conn.close()
        return False, "You cannot reuse your last 3 passwords for this service."
    
    # Update password in vault
    c.execute("UPDATE vault SET encrypted_password = ?, last_updated = ? WHERE user_id = ? AND service = ?",
              (encrypted, now, user_id, service))
    conn.commit()
    conn.close()
    
    # Store new password in history
    store_password_history(user_id, service, new_password)
    
    # Log activity
    log_activity(user_id, service, "updated")
    
    # Backup after change
    backup_vault(user_id, encryption_key)
    return True, "Password updated successfully."

def store_password_history(user_id, service, password):
    service = normalize_service(service)
    conn = sqlite3.connect('vaultsecure.db')
    c = conn.cursor()
    c.execute("INSERT INTO password_history (user_id, service, password_hash) VALUES (?, ?, ?)",
              (user_id, service, hash_password(password)))
    conn.commit()
    conn.close()

def is_password_reused(user_id, service, new_password):
    conn = sqlite3.connect('vaultsecure.db')
    c = conn.cursor()
    c.execute("SELECT password_hash FROM password_history WHERE user_id = ? AND service = ? ORDER BY changed_at DESC LIMIT 3",
              (user_id, service))
    last_hashes = [row[0] for row in c.fetchall()]
    conn.close()
    return hash_password(new_password) in last_hashes

def retrieve_passwords(username, encryption_key):
    cipher = AESCipher(encryption_key)
    conn = sqlite3.connect('vaultsecure.db')
    c = conn.cursor()
    c.execute("SELECT id FROM users WHERE username = ?", (username,))
    user_id = c.fetchone()
    if not user_id:
        return []
    c.execute("SELECT service, encrypted_password, last_updated FROM vault WHERE user_id = ?", (user_id[0],))
    rows = c.fetchall()
    conn.close()
    return [(service, cipher.decrypt(enc_pw), last_updated) for service, enc_pw, last_updated in rows]

def delete_password(username, service, encryption_key):
    service = normalize_service(service)
    conn = sqlite3.connect('vaultsecure.db')
    c = conn.cursor()
    c.execute("SELECT id FROM users WHERE username = ?", (username,))
    user_id = c.fetchone()
    if not user_id:
        conn.close()
        return False, "User not found."
    user_id = user_id[0]
    
    # Log activity before deleting
    log_activity(user_id, service, "deleted")
    
    c.execute("DELETE FROM vault WHERE user_id = ? AND service = ?", (user_id, service))
    conn.commit()
    conn.close()
    
    # Backup after change
    backup_vault(user_id, encryption_key)
    return True, "Password deleted successfully."

def backup_vault(user_id, encryption_key):
    import json
    # Fetch all vault entries for the user
    conn = sqlite3.connect('vaultsecure.db')
    c = conn.cursor()
    c.execute("SELECT service, encrypted_password, last_updated FROM vault WHERE user_id = ?", (user_id,))
    rows = c.fetchall()
    conn.close()
    
    # Serialize data
    data = json.dumps(rows).encode('utf-8')
    
    # Encrypt the backup data
    cipher = AESCipher(encryption_key)
    encrypted_data = cipher.encrypt(data.decode('utf-8')).encode('utf-8')
    
    # Store in backups table
    conn = sqlite3.connect('vaultsecure.db')
    c = conn.cursor()
    c.execute("INSERT INTO backups (user_id, backup_data) VALUES (?, ?)", (user_id, encrypted_data))
    conn.commit()
    conn.close()

def restore_vault_from_backup(username, encryption_key, backup_id=None):
    import json
    conn = sqlite3.connect('vaultsecure.db')
    c = conn.cursor()
    
    # Get user_id
    c.execute("SELECT id FROM users WHERE username = ?", (username,))
    user_id = c.fetchone()
    if not user_id:
        conn.close()
        return False, "User not found."
    user_id = user_id[0]
    
    # Get the backup (latest if backup_id is None)
    if backup_id is None:
        c.execute("SELECT backup_data FROM backups WHERE user_id = ? ORDER BY backup_time DESC LIMIT 1", (user_id,))
    else:
        c.execute("SELECT backup_data FROM backups WHERE user_id = ? AND id = ?", (user_id, backup_id))
    
    row = c.fetchone()
    if not row:
        conn.close()
        return False, "Backup not found."
    
    encrypted_data = row[0]
    
    # Decrypt backup data
    cipher = AESCipher(encryption_key)
    try:
        decrypted_json = cipher.decrypt(encrypted_data.decode('utf-8'))
        vault_entries = json.loads(decrypted_json)
    except Exception as e:
        conn.close()
        return False, f"Decryption failed: {e}"
    
    # Clear current vault for user
    c.execute("DELETE FROM vault WHERE user_id = ?", (user_id,))
    
    # Restore entries
    for service, encrypted_password, last_updated in vault_entries:
        c.execute("INSERT INTO vault (user_id, service, encrypted_password, last_updated) VALUES (?, ?, ?, ?)",
                  (user_id, service, encrypted_password, last_updated))
    
    conn.commit()
    conn.close()
    
    # Log restore activity
    log_activity(user_id, "vault", "restored")
    return True, "Vault restored from backup."

def list_backups(username):
    conn = sqlite3.connect('vaultsecure.db')
    c = conn.cursor()
    c.execute("SELECT id FROM users WHERE username = ?", (username,))
    user_id = c.fetchone()
    if not user_id:
        conn.close()
        return []
    user_id = user_id[0]
    c.execute("SELECT id, backup_time FROM backups WHERE user_id = ? ORDER BY backup_time DESC", (user_id,))
    backups = c.fetchall()
    conn.close()
    return backups  # List of (id, backup_time)

def change_master_password(username, old_pw, new_pw):
    """Change master password with salted hashing"""
    # Authenticate user
    if not authenticate_user(username, old_pw)[0]:
        return False, "Authentication failed."
    
    # Validate new password strength
    if len(new_pw) < 8:
        return False, "New password must be at least 8 characters long."
    
    conn = sqlite3.connect('vaultsecure.db')
    c = conn.cursor()
    c.execute("SELECT id FROM users WHERE username = ?", (username,))
    user_id = c.fetchone()
    if not user_id:
        conn.close()
        return False, "User not found."
    user_id = user_id[0]
    
    # Re-encrypt all vault entries with new key
    old_cipher = AESCipher(old_pw)
    new_cipher = AESCipher(new_pw)
    c.execute("SELECT id, encrypted_password FROM vault WHERE user_id = ?", (user_id,))
    rows = c.fetchall()
    
    for vault_id, enc_pw in rows:
        try:
            plain = old_cipher.decrypt(enc_pw)
            new_enc = new_cipher.encrypt(plain)
            c.execute("UPDATE vault SET encrypted_password = ? WHERE id = ?", (new_enc, vault_id))
        except Exception:
            conn.close()
            return False, "Key rotation failed. (Corrupted data?)"
    
    # Update password hash with new salt
    salt, password_hash = hash_password_with_salt(new_pw)
    c.execute("UPDATE users SET password_hash = ?, password_salt = ? WHERE id = ?", 
              (password_hash, salt, user_id))
    
    conn.commit()
    conn.close()
    return True, "Password changed and vault re-encrypted."

def is_mfa_enabled(username):
    conn = sqlite3.connect('vaultsecure.db')
    c = conn.cursor()
    # If mfa_secret exists and is not empty, MFA is enabled
    c.execute("SELECT mfa_secret FROM users WHERE username = ?", (username,))
    row = c.fetchone()
    conn.close()
    return bool(row and row[0])

def set_mfa_enabled(username, enabled):
    conn = sqlite3.connect('vaultsecure.db')
    c = conn.cursor()
    if enabled:
        # If enabling, ensure mfa_secret exists
        c.execute("SELECT mfa_secret FROM users WHERE username = ?", (username,))
        row = c.fetchone()
        if not row or not row[0]:
            new_secret = generate_mfa_secret()
            c.execute("UPDATE users SET mfa_secret = ? WHERE username = ?", (new_secret, username))
    else:
        # If disabling, clear mfa_secret
        c.execute("UPDATE users SET mfa_secret = NULL WHERE username = ?", (username,))
    conn.commit()
    conn.close()

def reset_mfa_secret(username):
    conn = sqlite3.connect('vaultsecure.db')
    c = conn.cursor()
    new_secret = generate_mfa_secret()
    c.execute("UPDATE users SET mfa_secret = ? WHERE username = ?", (new_secret, username))
    conn.commit()
    conn.close()

if __name__ == '__main__':
    create_tables()