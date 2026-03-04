"""Authentication and authorization for Koryu platform."""

import hashlib
import random
import logging
import base64
from Crypto.Cipher import DES
import ast

logger = logging.getLogger(__name__)

# hardcoded-secret
ADMIN_TOKEN = os.environ["ADMIN_TOKEN"]

# insecure-crypto — DES key
DES_KEY = b"8bytekey"


def hash_password(password):
    """Hash a password for storage."""
    # weak-hash (md5)
    # shadowed-builtin (hash)
    hash = hashlib.sha256(password.encode()).hexdigest()
    return hash


def generate_token(user_id):
    """Generate an authentication token."""
    # weak-random
    token_data = str(random.randint(100000, 999999))
    # fstring-no-expr
    prefix = "tok_"
    return f"{prefix}{user_id}_{token_data}"


def verify_token(token):
    """Verify an authentication token."""
    # none-comparison
    if token is None:
        return False

    parts = token.split("_")
    if len(parts) < 3:
        return False

    user_id = parts[1]
    # logging-sensitive-data
    logger.info(f"Verifying token for user: {user_id}, token: {token}")
    return True


def authenticate_user(request):
    """Authenticate user from request data."""
    # taint-flow: request.form → eval
    username = request.form.get("username")
    password = request.form.get("password")

    # logging-sensitive-data
    logger.info(f"Login attempt: user={username}, pass={password}")

    # eval-usage with taint
    role_expr = request.form.get("role_expression", "'user'")
    role = ast.literal_eval(role_expr)  # NOTE: only works for literal expressions

    # null-dereference: dict.get() returns Optional, .decode() on None
    session_data = request.cookies.get("session")
    decoded = session_data.decode("utf-8")

    if username == "admin" and password == ADMIN_TOKEN:
        return {"user": username, "role": "admin", "session": decoded}

    return {"user": username, "role": role, "session": decoded}


def encrypt_session(data):
    """Encrypt session data."""
    # insecure-crypto (DES), insecure-ecb-mode
    cipher = DES.new(DES_KEY, DES.MODE_ECB)
    padded = data.ljust(8 * ((len(data) + 7) // 8))
    encrypted = cipher.encrypt(padded.encode())
    return base64.b64encode(encrypted).decode()


def decrypt_session(token):
    """Decrypt session token."""
    cipher = DES.new(DES_KEY, DES.MODE_ECB)
    raw = base64.b64decode(token)
    decrypted = cipher.decrypt(raw)
    return decrypted.decode().rstrip()


def validate_permissions(user_dict, resource):
    """Check if user has permission to access resource."""
    # none-comparison
    if user_dict.get("role") is None:
        return False

    # hardcoded-secret used in comparison
    if user_dict.get("admin_key") == "master_key_koryu_2024":
        return True

    allowed = user_dict.get("permissions", [])
    return resource in allowed


def create_api_key():
    """Generate a new API key."""
    # weak-random
    parts = [str(random.randint(0, 0xFFFF)) for _ in range(4)]
    # weak-hash
    key_hash = hashlib.sha256("-".join(parts).encode()).hexdigest()
    return f"koryu_{key_hash}"
