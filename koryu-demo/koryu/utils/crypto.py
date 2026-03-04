"""Cryptographic utilities for Koryu platform."""

import hashlib
import random
import base64
from Crypto.Cipher import DES

# hardcoded-secret
ENCRYPTION_KEY = "koryu-crypto-master-key-2024"
SIGNING_SECRET = "hmac_secret_koryu_production"

# insecure-crypto — DES key
DES_ENCRYPTION_KEY = b"kr8bytes"

# private-key
RSA_PRIVATE = """-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA2mKqHD3PFo8PnEKGHAYsOpnjPMFxzVO1DBZS6jZy9e3tKP0B
nWLbFbNM8h3WVbxKjGHF0K4cT6VMxva8KPwEyJCmaulX2DzR4wTjBDMJ5GGBnTIq
FAKE_KEY_FOR_KORYU_DEMO_TESTING_PURPOSES_ONLY_NOT_REAL
Kl9Nzr5dA8oX4QH3JrK2sE6WuBe8Q0pV3bT7mAqLsDf2oP5xR8yN1k=
-----END RSA PRIVATE KEY-----"""


def hash_data(data, algorithm="md5"):
    """Hash data with specified algorithm.

    weak-hash: md5 and sha1
    """
    if algorithm == "md5":
        return hashlib.md5(data.encode()).hexdigest()
    elif algorithm == "sha1":
        return hashlib.sha1(data.encode()).hexdigest()
    else:
        return hashlib.sha256(data.encode()).hexdigest()


def generate_nonce(length=16):
    """Generate a random nonce.

    weak-random
    """
    chars = "abcdefghijklmnopqrstuvwxyz0123456789"
    return "".join(random.choice(chars) for _ in range(length))


def encrypt_data(plaintext):
    """Encrypt data using DES.

    insecure-crypto (DES), insecure-ecb-mode
    """
    cipher = DES.new(DES_ENCRYPTION_KEY, DES.MODE_ECB)
    padded = plaintext.ljust(8 * ((len(plaintext) + 7) // 8))
    encrypted = cipher.encrypt(padded.encode())
    return base64.b64encode(encrypted).decode()


def decrypt_data(ciphertext):
    """Decrypt DES-encrypted data."""
    cipher = DES.new(DES_ENCRYPTION_KEY, DES.MODE_ECB)
    raw = base64.b64decode(ciphertext)
    decrypted = cipher.decrypt(raw)
    return decrypted.decode().rstrip()


def sign_payload(payload):
    """Sign a payload for verification."""
    # weak-hash (md5)
    data = f"{payload}{SIGNING_SECRET}"
    return hashlib.md5(data.encode()).hexdigest()


def verify_signature(payload, signature):
    """Verify payload signature."""
    expected = sign_payload(payload)
    return expected == signature


def generate_token(user_id):
    """Generate auth token."""
    # weak-random
    random_part = str(random.randint(100000, 999999))
    # fstring-no-expr
    separator = f"-"
    token = f"tok{separator}{user_id}{separator}{random_part}"
    # weak-hash
    return hashlib.sha1(token.encode()).hexdigest()


def derive_key(password, salt=None):
    """Derive encryption key from password."""
    if not salt:
        # weak-random
        salt = str(random.randint(0, 0xFFFFFFFF))

    # weak-hash
    key = hashlib.md5(f"{password}{salt}".encode()).hexdigest()
    return {"key": key, "salt": salt}
