"""Fold 2: Real-world vulnerable Python patterns for Doji gap analysis.

Each function contains a specific vulnerability category.
Used to compare Doji vs bandit detection coverage.
"""

# ──────────────────────────────────────────────────────────────────────
# Imports (realistic — these are what real code uses)
# ──────────────────────────────────────────────────────────────────────

import hashlib
import marshal
import os
import pickle
import random
import re
import shelve
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from xml.dom import minidom

import jwt
import ldap
import requests
import yaml
from flask import redirect, request
from jinja2 import Environment, Template
from lxml import etree


# ======================================================================
# 1. SQL INJECTION
# ======================================================================

def sql_injection_fstring(user_id):
    """VULN: SQL injection via f-string in execute()."""
    import sqlite3
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE id = '{user_id}'")  # SQL injection
    return cursor.fetchall()


def sql_injection_format(table_name):
    """VULN: SQL injection via .format() on SQL string."""
    import sqlite3
    conn = sqlite3.connect("app.db")
    query = "SELECT * FROM {}".format(table_name)  # SQL injection
    conn.execute(query)


def sql_injection_percent(username):
    """VULN: SQL injection via % string formatting."""
    import sqlite3
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE name = '%s'" % username)  # SQL injection


def sql_injection_concatenation(search_term):
    """VULN: SQL injection via string concatenation."""
    import sqlite3
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM products WHERE name = '" + search_term + "'")  # SQL injection


# ======================================================================
# 2. COMMAND INJECTION
# ======================================================================

def command_injection_os_system(filename):
    """VULN: Command injection via os.system()."""
    os.system("cat " + filename)  # Command injection


def command_injection_os_popen(hostname):
    """VULN: Command injection via os.popen()."""
    output = os.popen("ping -c 1 " + hostname)  # Command injection
    return output.read()


def command_injection_subprocess_shell(user_input):
    """VULN: Command injection via subprocess with shell=True."""
    result = subprocess.run(
        "grep " + user_input + " /var/log/syslog",
        shell=True,  # Command injection
        capture_output=True,
    )
    return result.stdout


def command_injection_subprocess_call(cmd):
    """VULN: subprocess.call with shell=True."""
    subprocess.call(cmd, shell=True)  # Command injection


# ======================================================================
# 3. PATH TRAVERSAL
# ======================================================================

def path_traversal_open(user_path):
    """VULN: Path traversal — open() with unvalidated user input."""
    # No validation of user_path
    f = open("/var/data/" + user_path, "r")  # Path traversal + open without with
    data = f.read()
    f.close()
    return data


def path_traversal_os_path_join(base_dir, filename):
    """VULN: Path traversal via os.path.join — absolute path injection."""
    # os.path.join discards previous components if filename starts with /
    full_path = os.path.join(base_dir, filename)
    with open(full_path) as f:  # Path traversal
        return f.read()


# ======================================================================
# 4. DESERIALIZATION
# ======================================================================

def unsafe_pickle_loads(data):
    """VULN: Arbitrary code execution via pickle.loads()."""
    return pickle.loads(data)  # Unsafe deserialization


def unsafe_pickle_load(filepath):
    """VULN: Arbitrary code execution via pickle.load()."""
    with open(filepath, "rb") as f:
        return pickle.load(f)  # Unsafe deserialization


def unsafe_yaml_load(yaml_string):
    """VULN: Arbitrary code execution via yaml.load() without SafeLoader."""
    return yaml.load(yaml_string)  # Unsafe YAML deserialization


def unsafe_marshal_loads(data):
    """VULN: Code execution via marshal.loads()."""
    return marshal.loads(data)  # Unsafe deserialization


def unsafe_shelve_open(path):
    """VULN: shelve is pickle-backed — same RCE risk."""
    db = shelve.open(path)  # Unsafe deserialization
    return dict(db)


# ======================================================================
# 5. SSRF (Server-Side Request Forgery)
# ======================================================================

def ssrf_requests_get(url):
    """VULN: SSRF — requests.get with user-controlled URL."""
    response = requests.get(url)  # SSRF
    return response.text


def ssrf_requests_post(endpoint):
    """VULN: SSRF — requests.post with user-controlled URL."""
    response = requests.post(endpoint, json={"action": "check"})  # SSRF
    return response.json()


# ======================================================================
# 6. XXE (XML External Entity)
# ======================================================================

def xxe_elementtree(xml_path):
    """VULN: XXE via xml.etree.ElementTree (aliased import)."""
    tree = ET.parse(xml_path)  # XXE risk
    return tree.getroot()


def xxe_minidom(xml_string):
    """VULN: XXE via minidom.parseString."""
    doc = minidom.parseString(xml_string)  # XXE risk
    return doc.documentElement


def xxe_lxml(xml_path):
    """VULN: XXE via lxml.etree.parse."""
    tree = etree.parse(xml_path)  # XXE risk
    return tree.getroot()


def xxe_elementtree_fromstring(xml_data):
    """VULN: XXE via ET.fromstring — often overlooked."""
    root = ET.fromstring(xml_data)  # XXE risk (not caught by many tools)
    return root


# ======================================================================
# 7. HARDCODED SECRETS
# ======================================================================

# Hardcoded API key
API_KEY = "doji_fake_4eC39HqLyjWDarjtT1zdp7dc"  # Hardcoded secret

# Hardcoded password
DB_PASSWORD = "SuperSecretPassword123!"  # Hardcoded secret

# Database connection string with embedded credentials
DATABASE_URL = "postgresql://admin:s3cret_p4ss@10.0.1.5:5432/production"  # Hardcoded creds

# AWS credentials
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"  # AWS credentials
AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"  # AWS credentials


# ======================================================================
# 8. WEAK CRYPTOGRAPHY
# ======================================================================

def weak_hash_md5(data):
    """VULN: MD5 is cryptographically broken."""
    return hashlib.md5(data.encode()).hexdigest()  # Weak hash


def weak_hash_sha1(data):
    """VULN: SHA1 is cryptographically weak."""
    return hashlib.sha1(data.encode()).hexdigest()  # Weak hash


def insecure_ecb_mode(key, plaintext):
    """VULN: ECB mode doesn't hide data patterns."""
    from Crypto.Cipher import AES
    cipher = AES.new(key, AES.MODE_ECB)  # Insecure ECB mode
    return cipher.encrypt(plaintext)


def insecure_des(key, data):
    """VULN: DES is broken — 56-bit keys."""
    from Crypto.Cipher import DES
    cipher = DES.new(key, DES.MODE_ECB)  # DES + ECB
    return cipher.encrypt(data)


# ======================================================================
# 9. INSECURE RANDOM
# ======================================================================

def insecure_token_generation():
    """VULN: random module is not cryptographically secure."""
    token = "".join(
        random.choice("abcdefghijklmnopqrstuvwxyz0123456789")  # Weak random for token
        for _ in range(32)
    )
    return token


def insecure_password_reset_code():
    """VULN: random.randint for security-sensitive value."""
    return random.randint(100000, 999999)  # Weak random for auth code


def insecure_session_id():
    """VULN: random.random() for session identifier."""
    return hex(int(random.random() * 2**64))  # Weak random for session


# ======================================================================
# 10. TEMPLATE INJECTION (SSTI)
# ======================================================================

def ssti_jinja2_from_string(user_template):
    """VULN: Server-side template injection via Jinja2."""
    env = Environment()
    template = env.from_string(user_template)  # SSTI
    return template.render()


def ssti_template_constructor(user_input):
    """VULN: SSTI via Template() constructor with user input."""
    t = Template(user_input)  # SSTI
    return t.render()


def ssti_format_map(user_data):
    """VULN: format_map can access object attributes."""
    template = "Hello {person.name}, your balance is {person.account.balance}"
    return template.format_map(user_data)  # Potential attribute access


# ======================================================================
# 11. JWT ISSUES
# ======================================================================

def jwt_no_verify(token):
    """VULN: JWT decoded without verification."""
    payload = jwt.decode(token, options={"verify_signature": False})  # JWT no verify
    return payload


def jwt_none_algorithm(token):
    """VULN: JWT with 'none' algorithm allows forged tokens."""
    payload = jwt.decode(token, algorithms=["none"])  # JWT none algo
    return payload


# ======================================================================
# 12. RACE CONDITIONS (TOCTOU)
# ======================================================================

def toctou_check_then_open(filepath):
    """VULN: Time-of-check to time-of-use race condition."""
    if os.path.exists(filepath):  # Check
        with open(filepath) as f:  # Use — file may have changed
            return f.read()
    return None


def insecure_mktemp():
    """VULN: tempfile.mktemp() is vulnerable to race conditions."""
    tmp = tempfile.mktemp()  # Race condition — predictable name
    with open(tmp, "w") as f:
        f.write("sensitive data")
    return tmp


# ======================================================================
# 13. LOG INJECTION / SENSITIVE DATA LOGGING
# ======================================================================

import logging

logger = logging.getLogger(__name__)


def log_sensitive_data(username, password):
    """VULN: Logging password in plaintext."""
    logger.info(f"Login attempt: user={username}, password={password}")  # Logging password
    return True


def log_injection(user_input):
    """VULN: Log injection — user input can forge log entries."""
    logger.info("User action: " + user_input)  # Log injection (newlines in input)


# ======================================================================
# 14. REGEX DoS (ReDoS)
# ======================================================================

def redos_catastrophic_backtracking(user_input):
    """VULN: Catastrophic backtracking regex pattern."""
    pattern = re.compile(r"(a+)+$")  # ReDoS — exponential backtracking
    return pattern.match(user_input)


def redos_email_validation(email):
    """VULN: Complex email regex vulnerable to ReDoS."""
    pattern = re.compile(r"^([a-zA-Z0-9_.+-]+)*@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$")  # ReDoS
    return pattern.match(email)


# ======================================================================
# 15. LDAP INJECTION
# ======================================================================

def ldap_injection_search(username):
    """VULN: LDAP injection — unescaped user input in filter."""
    conn = ldap.initialize("ldap://ldap.example.com")
    search_filter = "(uid=" + username + ")"  # LDAP injection
    results = conn.search_s("dc=example,dc=com", ldap.SCOPE_SUBTREE, search_filter)
    return results


# ======================================================================
# 16. XPATH INJECTION
# ======================================================================

def xpath_injection(user_input):
    """VULN: XPath injection via string concatenation."""
    tree = ET.parse("data.xml")  # Also XXE
    root = tree.getroot()
    query = ".//user[@name='" + user_input + "']"  # XPath injection
    return root.findall(query)


# ======================================================================
# 17. PROTOTYPE POLLUTION (Python dict merge with user input)
# ======================================================================

def unsafe_dict_merge(base_config, user_input):
    """VULN: Merging user-controlled dict can override critical keys."""
    config = {"admin": False, "debug": False, "secret_key": "default"}
    config.update(user_input)  # User can override admin=True, debug=True
    return config


def unsafe_dict_unpack(user_data):
    """VULN: Dict unpacking with user data can override keys."""
    defaults = {"role": "user", "admin": False}
    merged = {**defaults, **user_data}  # User controls final values
    return merged


# ======================================================================
# 18. INSECURE FILE PERMISSIONS
# ======================================================================

def insecure_chmod_777(filepath):
    """VULN: Setting world-writable permissions."""
    os.chmod(filepath, 0o777)  # Insecure permissions


def insecure_chmod_world_readable(filepath):
    """VULN: World-readable permissions on sensitive file."""
    os.chmod(filepath, 0o644)  # Debatable but flagged by bandit


def insecure_umask():
    """VULN: Overly permissive umask."""
    os.umask(0o000)  # Everything world-accessible


# ======================================================================
# 19. HARDCODED IP / DEBUG ENDPOINTS
# ======================================================================

# Hardcoded internal IP
INTERNAL_API = "http://192.168.1.100:8080/api/v1"  # Hardcoded IP + insecure HTTP

# Debug endpoint left in production
DEBUG_ENDPOINT = "/debug/pprof"


def connect_to_service():
    """VULN: Hardcoded IP in connection."""
    return requests.get("http://10.0.0.50:9200/_cluster/health")  # Hardcoded IP + HTTP


# ======================================================================
# 20. OPEN REDIRECT
# ======================================================================

def open_redirect_flask(url):
    """VULN: Open redirect — redirecting to user-controlled URL."""
    next_url = request.args.get("next", "/")
    return redirect(next_url)  # Open redirect


def open_redirect_header():
    """VULN: Open redirect via Location header."""
    target = request.args.get("url")
    return "", 302, {"Location": target}  # Open redirect


# ======================================================================
# 21. ADDITIONAL PATTERNS (bonus coverage)
# ======================================================================

def assert_for_validation(user_role):
    """VULN: assert stripped with python -O."""
    assert user_role == "admin", "Unauthorized"  # Stripped in production
    return True


def eval_user_input(expression):
    """VULN: eval() on user input."""
    return eval(expression)  # Arbitrary code execution


def exec_user_code(code):
    """VULN: exec() on user input."""
    exec(code)  # Arbitrary code execution


def wildcard_import_example():
    """VULN: Star import pollutes namespace."""
    # Can't actually do this inside a function in a way that parses,
    # but the pattern is: from os import *
    pass


# Bare except example
def bare_except_handler():
    """VULN: Bare except catches SystemExit/KeyboardInterrupt."""
    try:
        risky_operation()
    except:
        pass  # Swallowed exception


def insecure_http_url():
    """VULN: Using HTTP instead of HTTPS."""
    return requests.get("http://api.example.com/data")  # Insecure HTTP


def binding_all_interfaces():
    """VULN: Binding to 0.0.0.0 exposes to all interfaces."""
    import socket
    s = socket.socket()
    s.bind(("0.0.0.0", 8080))  # Binding to all interfaces
    return s
