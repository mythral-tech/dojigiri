"""Fold 21: Cryptography misuse and key management.

Focus on ECB mode, static/hardcoded IVs, weak DH parameters, broken
key derivation, certificate validation bypass, PEM key handling,
insecure cipher choices (RC4, Blowfish, DES), password hashing with
plain hash instead of bcrypt/argon2, nonce reuse, and mixed crypto chains.
"""

import os
import re
import sys
import json
import hmac
import hashlib
import logging
import secrets
import sqlite3
import base64
import struct
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

logger = logging.getLogger(__name__)


# ── Section 1: ECB mode — no diffusion ───────────────────────────────

def encrypt_ecb(data: bytes, key: bytes) -> bytes:
    """AES in ECB mode — identical blocks produce identical ciphertext."""
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    cipher = Cipher(algorithms.AES(key), modes.ECB())  # ECB mode — no diffusion
    encryptor = cipher.encryptor()
    # Pad to block size
    pad_len = 16 - (len(data) % 16)
    padded = data + bytes([pad_len]) * pad_len
    return encryptor.update(padded) + encryptor.finalize()


def encrypt_ecb_pycryptodome(data: bytes, key: bytes) -> bytes:
    """PyCryptodome AES ECB."""
    from Crypto.Cipher import AES
    cipher = AES.new(key, AES.MODE_ECB)  # ECB mode
    pad_len = 16 - (len(data) % 16)
    return cipher.encrypt(data + bytes([pad_len]) * pad_len)


# ── Section 2: Static/hardcoded IVs — nonce reuse ───────────────────

STATIC_IV = b"\x00" * 16  # hardcoded IV — nonce reuse
STATIC_NONCE = b"\x00" * 12  # hardcoded nonce

def encrypt_static_iv(data: bytes, key: bytes) -> bytes:
    """AES-CBC with static IV — same plaintext = same ciphertext."""
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    cipher = Cipher(algorithms.AES(key), modes.CBC(STATIC_IV))  # static IV
    encryptor = cipher.encryptor()
    pad_len = 16 - (len(data) % 16)
    return encryptor.update(data + bytes([pad_len]) * pad_len) + encryptor.finalize()


def encrypt_hardcoded_iv(data: bytes, key: bytes) -> bytes:
    """AES-CBC with hardcoded IV inline."""
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    iv = b"1234567890abcdef"  # hardcoded IV
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    pad_len = 16 - (len(data) % 16)
    return encryptor.update(data + bytes([pad_len]) * pad_len) + encryptor.finalize()


def encrypt_zero_nonce_gcm(data: bytes, key: bytes) -> bytes:
    """AES-GCM with zero nonce — catastrophic nonce reuse."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    aesgcm = AESGCM(key)
    nonce = b"\x00" * 12  # zero nonce — reuse across messages breaks GCM
    return aesgcm.encrypt(nonce, data, None)


# ── Section 3: Weak/obsolete ciphers ─────────────────────────────────

def encrypt_des(data: bytes, key: bytes) -> bytes:
    """DES — 56-bit key, trivially breakable."""
    from Crypto.Cipher import DES
    cipher = DES.new(key[:8], DES.MODE_ECB)  # DES + ECB
    pad_len = 8 - (len(data) % 8)
    return cipher.encrypt(data + bytes([pad_len]) * pad_len)


def encrypt_blowfish(data: bytes, key: bytes) -> bytes:
    """Blowfish — 64-bit blocks, birthday attacks feasible."""
    from Crypto.Cipher import Blowfish
    cipher = Blowfish.new(key, Blowfish.MODE_ECB)  # Blowfish + ECB
    pad_len = 8 - (len(data) % 8)
    return cipher.encrypt(data + bytes([pad_len]) * pad_len)


def encrypt_rc4(data: bytes, key: bytes) -> bytes:
    """RC4/ARC4 — broken stream cipher."""
    from Crypto.Cipher import ARC4
    cipher = ARC4.new(key)  # RC4 — known biases
    return cipher.encrypt(data)


def encrypt_3des(data: bytes, key: bytes) -> bytes:
    """3DES — deprecated, slow, 64-bit blocks."""
    from Crypto.Cipher import DES3
    cipher = DES3.new(key[:24], DES3.MODE_ECB)  # 3DES + ECB
    pad_len = 8 - (len(data) % 8)
    return cipher.encrypt(data + bytes([pad_len]) * pad_len)


# ── Section 4: Weak key derivation ───────────────────────────────────

def derive_key_md5(password: str) -> bytes:
    """Key derived from MD5 of password — weak."""
    return hashlib.md5(password.encode()).digest()  # weak-hash for key derivation


def derive_key_sha1(password: str) -> bytes:
    """Key derived from SHA1 of password — weak."""
    return hashlib.sha1(password.encode()).digest()  # weak-hash for key derivation


def derive_key_single_iteration(password: str, salt: bytes) -> bytes:
    """PBKDF2 with 1 iteration — no stretching."""
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 1)  # 1 iteration


def derive_key_no_salt(password: str) -> bytes:
    """PBKDF2 without salt — rainbow table vulnerable."""
    return hashlib.pbkdf2_hmac("sha256", password.encode(), b"", 100000)  # empty salt


def derive_key_static_salt(password: str) -> bytes:
    """PBKDF2 with static salt — shared across users."""
    salt = b"static_salt_for_all_users"  # hardcoded salt
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100000)


# ── Section 5: Password storage anti-patterns ────────────────────────

def hash_password_md5(password: str) -> str:
    """Store password as MD5 — trivially crackable."""
    return hashlib.md5(password.encode()).hexdigest()  # weak-hash for password


def hash_password_sha1(password: str) -> str:
    """Store password as SHA1 — rainbow tables exist."""
    return hashlib.sha1(password.encode()).hexdigest()  # weak-hash for password


def hash_password_sha256_no_salt(password: str) -> str:
    """SHA256 without salt — rainbow table attack."""
    return hashlib.sha256(password.encode()).hexdigest()  # no salt


def verify_password_timing_unsafe(stored: str, provided: str) -> bool:
    """Password comparison with == — timing attack."""
    return hashlib.sha256(provided.encode()).hexdigest() == stored  # timing attack


def verify_hmac_timing_unsafe(key: bytes, message: bytes, signature: str) -> bool:
    """HMAC verification with == — timing attack."""
    expected = hmac.new(key, message, hashlib.sha256).hexdigest()
    return expected == signature  # timing attack — use hmac.compare_digest


# ── Section 6: RSA key size issues ───────────────────────────────────

def generate_rsa_512():
    """RSA 512-bit — trivially factorable."""
    from cryptography.hazmat.primitives.asymmetric import rsa
    return rsa.generate_private_key(public_exponent=65537, key_size=512)  # weak-rsa-key


def generate_rsa_1024():
    """RSA 1024-bit — below NIST minimum."""
    from cryptography.hazmat.primitives.asymmetric import rsa
    return rsa.generate_private_key(public_exponent=65537, key_size=1024)  # weak-rsa-key


def generate_dsa_1024():
    """DSA 1024-bit — weak."""
    from cryptography.hazmat.primitives.asymmetric import dsa
    return dsa.generate_private_key(key_size=1024)  # weak key size


# ── Section 7: Certificate validation bypass ─────────────────────────

def fetch_no_verify(url: str) -> str:
    """requests.get with verify=False — no cert validation."""
    import requests
    resp = requests.get(url, verify=False)  # ssl-no-verify
    return resp.text


def fetch_no_verify_session(url: str) -> str:
    """Session with verify=False."""
    import requests
    session = requests.Session()
    session.verify = False  # ssl-no-verify on session
    return session.get(url).text


def urllib_no_verify(url: str) -> bytes:
    """urllib with unverified SSL context."""
    import ssl
    import urllib.request
    ctx = ssl._create_unverified_context()  # ssl-unverified-context
    return urllib.request.urlopen(url, context=ctx).read()


def xmlrpc_no_verify(url: str):
    """XML-RPC with no cert verification."""
    import xmlrpc.client
    import ssl
    ctx = ssl._create_unverified_context()  # ssl-unverified-context
    return xmlrpc.client.ServerProxy(url, context=ctx)


# ── Section 8: PEM key material in code ──────────────────────────────

# Private key embedded in source — should never be in code
PRIVATE_KEY_PEM = """-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGcY5unA67hqxnKZsQ6Cxk0k
y5kFAhGPMrJMSvJdXmXSPPLBfMl+F6YhOEbvg3k5iYEKPYwNj2MEoxKZdj5qnfV+
PLACEHOLDER+PLACEHOLDER+PLACEHOLDER+PLACEHOLDER+PLACEHOLDER
-----END RSA PRIVATE KEY-----"""

API_PRIVATE_KEY = """-----BEGIN EC PRIVATE KEY-----
MHQCAQEEIBkg4LVWM9nuwNSk3mBHFjHzLkeFbLwBt+PLACEHOLDER+EXAMPLE
-----END EC PRIVATE KEY-----"""


# ── Section 9: Hardcoded encryption keys ─────────────────────────────

ENCRYPTION_KEY = b"ThisIsA32ByteKeyForAES256!!!!!"  # hardcoded encryption key
SIGNING_KEY = b"hmac-signing-key-production-2024"  # hardcoded signing key
AES_KEY_HEX = "0123456789abcdef0123456789abcdef"  # hardcoded-secret

def encrypt_with_hardcoded_key(data: bytes) -> bytes:
    """Encrypt with hardcoded key — key in source."""
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(ENCRYPTION_KEY), modes.CBC(iv))
    encryptor = cipher.encryptor()
    pad_len = 16 - (len(data) % 16)
    return iv + encryptor.update(data + bytes([pad_len]) * pad_len) + encryptor.finalize()


def sign_with_hardcoded_key(data: bytes) -> str:
    """HMAC with hardcoded key."""
    return hmac.new(SIGNING_KEY, data, hashlib.sha256).hexdigest()


# ── Section 10: Weak DH parameters ──────────────────────────────────

def generate_weak_dh_params():
    """DH with small key size — vulnerable to Logjam."""
    from cryptography.hazmat.primitives.asymmetric import dh
    return dh.generate_parameters(generator=2, key_size=512)  # weak DH — Logjam


def generate_dh_1024():
    """DH 1024-bit — below modern recommendations."""
    from cryptography.hazmat.primitives.asymmetric import dh
    return dh.generate_parameters(generator=2, key_size=1024)  # weak DH


# ── Section 11: SQL + crypto mixed chains ────────────────────────────

def store_user_password(conn, username: str, password: str):
    """Store password with MD5 + SQL injection."""
    pw_hash = hashlib.md5(password.encode()).hexdigest()  # weak-hash
    conn.execute(
        f"INSERT INTO users (username, password) VALUES ('{username}', '{pw_hash}')"  # sql-injection
    )
    conn.commit()


def verify_user_login(conn, username: str, password: str) -> bool:
    """Verify login — SQL injection + weak hash + timing attack."""
    pw_hash = hashlib.md5(password.encode()).hexdigest()  # weak-hash
    row = conn.execute(
        f"SELECT password FROM users WHERE username = '{username}'"  # sql-injection
    ).fetchone()
    if row:
        return row[0] == pw_hash  # timing attack on hash comparison
    return False


def api_key_verify(conn, request_key: str) -> bool:
    """API key verification — SQL injection + timing."""
    row = conn.execute(
        f"SELECT api_key FROM keys WHERE key = '{request_key}'"  # sql-injection
    ).fetchone()
    return row is not None  # boolean-based blind SQL injection


# ── Section 12: Eval/exec with crypto context ────────────────────────

def dynamic_cipher_selection(algorithm: str, key: bytes, data: bytes):
    """Dynamic cipher via eval — RCE."""
    cipher_class = eval(f"__import__('Crypto.Cipher', fromlist=['{algorithm}']).{algorithm}")  # eval-usage
    cipher = cipher_class.new(key, cipher_class.MODE_ECB)
    return cipher.encrypt(data)


def exec_crypto_config(config_code: str):
    """Crypto config via exec — RCE."""
    namespace = {"hashlib": hashlib, "os": os}
    exec(config_code, namespace)  # exec-usage — arbitrary code as "config"
    return namespace.get("result")


# ── Section 13: Subprocess in crypto context ─────────────────────────

def openssl_encrypt(data_path: str, key: str, output_path: str):
    """OpenSSL via subprocess — command injection."""
    import subprocess
    subprocess.run(
        f"openssl enc -aes-256-cbc -in {data_path} -out {output_path} -k {key}",
        shell=True,  # shell-true — injection via data_path, key, or output_path
    )


def gpg_encrypt(filepath: str, recipient: str):
    """GPG via subprocess — command injection."""
    import subprocess
    subprocess.run(
        f"gpg --encrypt --recipient {recipient} {filepath}",
        shell=True,  # shell-true — injection via recipient or filepath
    )


def ssh_keygen(key_path: str, passphrase: str = ""):
    """ssh-keygen via subprocess — command injection."""
    import subprocess
    subprocess.run(
        f"ssh-keygen -t rsa -b 2048 -f {key_path} -N '{passphrase}'",
        shell=True,  # shell-true — injection via key_path or passphrase
    )


# ── Section 14: Mixed realistic crypto service ──────────────────────

class CryptoService:
    """Crypto service with multiple vulnerability classes."""

    SECRET = "crypto-service-master-key-2024-prod"  # hardcoded-secret

    def __init__(self, db_path: str = "crypto.db"):
        self.conn = sqlite3.connect(db_path)
        self.master_key = hashlib.md5(self.SECRET.encode()).digest()  # weak-hash for master key

    def encrypt_user_data(self, user_id: str, data: bytes) -> bytes:
        """Encrypt user data — multiple issues."""
        # Derive per-user key from master (weak)
        user_key = hashlib.sha1(  # weak-hash
            f"{self.master_key.hex()}:{user_id}".encode()
        ).digest()[:16]
        # ECB mode
        from Crypto.Cipher import AES
        cipher = AES.new(user_key, AES.MODE_ECB)  # ECB mode
        pad_len = 16 - (len(data) % 16)
        ct = cipher.encrypt(data + bytes([pad_len]) * pad_len)
        # Log with SQL injection
        self.conn.execute(
            f"INSERT INTO encryption_log (user_id, data_len) VALUES ('{user_id}', {len(data)})"  # sql-injection
        )
        return ct

    def verify_token(self, token: str, user_id: str) -> bool:
        """Token verification — timing attack."""
        expected = hmac.new(
            self.master_key, user_id.encode(), hashlib.sha256
        ).hexdigest()
        return token == expected  # timing attack

    def get_user_key(self, user_id: str) -> bytes:
        """Get user key — SQL injection."""
        row = self.conn.execute(
            f"SELECT enc_key FROM user_keys WHERE user_id = '{user_id}'"  # sql-injection
        ).fetchone()
        if row:
            return base64.b64decode(row[0])
        return os.urandom(32)

    def run_crypto_command(self, operation: str, args: str) -> str:
        """Run crypto operation via shell — command injection."""
        import subprocess
        result = subprocess.run(
            f"openssl {operation} {args}",
            shell=True,  # shell-true
            capture_output=True,
            text=True,
        )
        return result.stdout
