import os
import sqlite3
import uuid
import re
import secrets
import string
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from tqdm import tqdm

DB_FILE = "passwords.db"
CHUNK_SIZE = 4 * 1024 * 1024  # 4MB chunks for encryption/decryption

# --- Database and Password functions are unchanged ---
def generate_strong_password(length=32):
    alphabet = string.ascii_letters + string.digits + string.punctuation
    safe_alphabet = alphabet.replace('"', '').replace("'", "").replace('\\', '')
    password = ''.join(secrets.choice(safe_alphabet) for _ in range(length))
    return password

def init_db():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS file_keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file_uuid TEXT NOT NULL UNIQUE,
            original_filename TEXT NOT NULL,
            password TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    conn.close()

def save_key(file_uuid, original_filename, password):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    try:
        cursor.execute("INSERT INTO file_keys (file_uuid, original_filename, password) VALUES (?, ?, ?)", (file_uuid, original_filename, password))
        conn.commit()
        print(f"✅ Securely saved key for '{original_filename}'.")
    except sqlite3.IntegrityError:
        print("Error: This UUID already exists in the database.")
    finally:
        conn.close()

def get_key_data(file_uuid):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT password, original_filename FROM file_keys WHERE file_uuid = ?", (file_uuid,))
    result = cursor.fetchone()
    conn.close()
    return result if result else (None, None)

def list_keys():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT file_uuid, original_filename, created_at FROM file_keys ORDER BY created_at DESC")
    results = cursor.fetchall()
    conn.close()
    if not results:
        print("No keys found in the database."); return
    print("\n--- Stored File Keys ---")
    for row in results:
        print(f"ID: {row[0]}\n  Original Name: {row[1]}\n  Saved On: {row[2]}\n")
    print("------------------------")

# --- Streaming Encryption/Decryption ---

def encrypt_file(input_path, output_path, password):
    """Encrypts a file in chunks to handle any size."""
    try:
        salt = os.urandom(16)
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=480000)
        key = kdf.derive(password.encode())
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)
        
        file_size = os.path.getsize(input_path)

        with open(input_path, 'rb') as f_in, open(output_path, 'wb') as f_out:
            f_out.write(salt)
            f_out.write(nonce)
            
            with tqdm(total=file_size, unit='B', unit_scale=True, unit_divisor=1024, desc=f"Encrypting '{os.path.basename(input_path)}'") as progress:
                while True:
                    chunk = f_in.read(CHUNK_SIZE)
                    if not chunk:
                        break
                    encrypted_chunk = aesgcm.encrypt(nonce, chunk, None)
                    f_out.write(encrypted_chunk)
                    # We have to update the nonce for the next chunk in GCM
                    nonce = (int.from_bytes(nonce, 'big') + 1).to_bytes(12, 'big')
                    progress.update(len(chunk))

        print(f"Encryption complete. Output: {output_path}")
        return True
    except Exception as e:
        print(f"An error occurred during encryption: {e}")
        return False

def decrypt_file(input_path, output_path, password):
    """Decrypts a file in chunks to handle any size."""
    try:
        file_size = os.path.getsize(input_path)
        with open(input_path, 'rb') as f_in, open(output_path, 'wb') as f_out:
            salt = f_in.read(16)
            nonce = f_in.read(12)
            
            kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=480000)
            key = kdf.derive(password.encode())
            aesgcm = AESGCM(key)
            
            # The total size to decrypt is the file size minus the salt and nonce
            with tqdm(total=file_size - 28, unit='B', unit_scale=True, unit_divisor=1024, desc=f"Decrypting '{os.path.basename(input_path)}'") as progress:
                while True:
                    # GCM ciphertext is 16 bytes longer (auth tag) than plaintext
                    chunk = f_in.read(CHUNK_SIZE + 16)
                    if not chunk:
                        break
                    decrypted_chunk = aesgcm.decrypt(nonce, chunk, None)
                    f_out.write(decrypted_chunk)
                    # Update nonce for the next chunk
                    nonce = (int.from_bytes(nonce, 'big') + 1).to_bytes(12, 'big')
                    progress.update(len(chunk))

        print(f"✅ Decryption successful. File restored to: {output_path}")
        return True
    except Exception as e:
        print(f"❌ Decryption failed: {e}. The password may be incorrect or the file is corrupt.")
        return False