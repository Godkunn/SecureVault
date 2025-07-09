import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
import logging

logging.basicConfig(filename='app.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

KDF_DKLEN = 32 # 32 bytes for AES-256 key
KDF_N = 2**14
KDF_R = 8
KDF_P = 1

def _derive_aes_key(pass_key_from_auth):
    """
    Derives a final AES key from the pass_key provided by auth.py.
    This ensures the key is exactly KDF_DKLEN bytes for AES,
    and allows for further hardening if needed.
    """

    if len(pass_key_from_auth) != KDF_DKLEN:
        logging.warning(f"Pass key from auth.py is not {KDF_DKLEN} bytes. Re-deriving.")
        kdf = Scrypt(
            salt=b'file_aes_derivation_salt_unique_per_system',
            length=KDF_DKLEN,
            n=KDF_N,
            r=KDF_R,
            p=KDF_P,
            backend=default_backend()
        )
        return kdf.derive(pass_key_from_auth)
    return pass_key_from_auth


def encrypt_file(source_path, dest_path, user_pass_key):
    """
    Encrypts a file using AES-256 GCM.
    Includes a unique nonce and authentication tag within the encrypted file.
    """
    if not os.path.exists(source_path):
        raise FileNotFoundError(f"Source file not found: {source_path}")

    encryption_key = _derive_aes_key(user_pass_key)
    nonce = os.urandom(12) 
    cipher = Cipher(algorithms.AES(encryption_key), modes.GCM(nonce), backend=default_backend())
    encryptor = cipher.encryptor()

    try:
        with open(source_path, 'rb') as f_in:
            plaintext = f_in.read()

        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        tag = encryptor.tag 

        with open(dest_path, 'wb') as f_out:
            f_out.write(nonce)
            f_out.write(tag)
            f_out.write(ciphertext)
        logging.info(f"File '{os.path.basename(source_path)}' encrypted to '{os.path.basename(dest_path)}'.")
    except Exception as e:
        logging.error(f"Error encrypting file '{os.path.basename(source_path)}': {e}")
        raise

def decrypt_file(encrypted_file_path, user_pass_key):
    """
    Decrypts an encrypted file using AES-256 GCM.
    Performs integrity verification automatically as part of GCM decryption.
    Returns the decrypted bytes.
    """
    if not os.path.exists(encrypted_file_path):
        raise FileNotFoundError(f"Encrypted file not found: {encrypted_file_path}")

    decryption_key = _derive_aes_key(user_pass_key)

    try:
        with open(encrypted_file_path, 'rb') as f_in:
            nonce = f_in.read(12) 
            if len(nonce) != 12:
                raise ValueError("Invalid encrypted file format: nonce length mismatch.")
            
            tag = f_in.read(16) 
            if len(tag) != 16:
                raise ValueError("Invalid encrypted file format: tag length mismatch.")

            ciphertext = f_in.read() 

        cipher = Cipher(algorithms.AES(decryption_key), modes.GCM(nonce, tag), backend=default_backend())
        decryptor = cipher.decryptor()

        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        logging.info(f"File '{os.path.basename(encrypted_file_path)}' decrypted successfully.")
        return plaintext
    except Exception as e:
        logging.error(f"Error decrypting file '{os.path.basename(encrypted_file_path)}': {e}")
        
        if "InvalidTag" in str(e):
            raise ValueError("File integrity check failed. Data may be tampered with or key is wrong.")
        raise 
def verify_file_integrity(encrypted_file_path, original_hash_file_path=None, user_pass_key=None):
    """
    Verifies the integrity of an encrypted file.
    For AEAD (AES-GCM), successful decryption implies integrity.
    original_hash_file_path is unused for this AEAD-based integrity check.
    """
    if not user_pass_key:
        raise ValueError("User's pass key is required for integrity verification.")

    try:
        decrypt_file(encrypted_file_path, user_pass_key)
        logging.info(f"Integrity check passed for '{os.path.basename(encrypted_file_path)}' (via decryption).")
        return True
    except ValueError as e: 
        logging.warning(f"Integrity check FAILED for '{os.path.basename(encrypted_file_path)}': {e}")
        raise 
    except Exception as e:
        logging.error(f"Unexpected error during integrity check for '{os.path.basename(encrypted_file_path)}': {e}")
        raise