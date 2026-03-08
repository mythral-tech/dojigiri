"""Fold 12: Protocol handlers, crypto misuse, process control, and injection
via less-common stdlib modules.

Targets: http.server request handlers, socketserver, xmlrpc, ctypes beyond
LoadLibrary, signal handler races, multiprocessing shared state, tempfile
misuse beyond mktemp, logging config injection, struct unpack overflow,
platform/sysconfig info leak, webbrowser beyond open, and code object
manipulation.
"""

import os
import re
import sys
import json
import hmac
import time
import struct
import socket
import pickle
import sqlite3
import hashlib
import logging
import secrets
import marshal
import tempfile
import subprocess
import http.server
import http.cookies
import socketserver
import xmlrpc.client
import xmlrpc.server
import multiprocessing
import signal
import ctypes
import code
import cgi
import platform
import sysconfig
from pathlib import Path
from typing import Any, Dict, List, Optional
from xml.etree.ElementTree import fromstring as xml_from_str  # aliased XXE


logger = logging.getLogger(__name__)


# ── Section 1: http.server request handler vulnerabilities ───────────

class VulnerableHandler(http.server.BaseHTTPRequestHandler):
    """HTTP request handler with multiple security issues."""

    def do_GET(self):
        """Path traversal + XSS in error response."""
        # Path traversal via URL path
        filepath = Path("/var/www") / self.path.lstrip("/")
        if filepath.exists():
            self.send_response(200)
            self.end_headers()
            self.wfile.write(filepath.read_bytes())  # path traversal — no validation
        else:
            self.send_response(404)
            self.end_headers()
            # XSS — reflected path in response
            self.wfile.write(f"<h1>Not found: {self.path}</h1>".encode())

    def do_POST(self):
        """Deserialization of POST body."""
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)

        content_type = self.headers.get("Content-Type", "")
        if content_type == "application/x-pickle":
            data = pickle.loads(body)  # pickle-unsafe from HTTP request
        elif content_type == "application/json":
            data = json.loads(body)
        else:
            data = body

        self.send_response(200)
        self.end_headers()
        self.wfile.write(json.dumps({"received": str(data)}).encode())


def start_http_server(port: int = 8080):
    """Start HTTP server on all interfaces."""
    server = http.server.HTTPServer(("0.0.0.0", port), VulnerableHandler)  # bind-all-interfaces
    server.serve_forever()


# ── Section 2: socketserver patterns ─────────────────────────────────

class CommandHandler(socketserver.StreamRequestHandler):
    """TCP handler that executes received commands."""

    def handle(self):
        data = self.rfile.readline().strip().decode()
        # Command injection from network input
        result = subprocess.run(
            data,
            shell=True,  # shell-true from network
            capture_output=True,
            text=True,
        )
        self.wfile.write(result.stdout.encode())


class PickleHandler(socketserver.BaseRequestHandler):
    """TCP handler that deserializes pickled data."""

    def handle(self):
        data = self.request.recv(4096)
        obj = pickle.loads(data)  # pickle-unsafe from network
        self.request.sendall(json.dumps(str(obj)).encode())


def start_tcp_server(port: int = 9090):
    """Start TCP server on all interfaces."""
    server = socketserver.TCPServer(("0.0.0.0", port), CommandHandler)  # bind-all-interfaces
    server.serve_forever()


# ── Section 3: xmlrpc exposure ───────────────────────────────────────

def create_xmlrpc_server():
    """XML-RPC server exposing dangerous functions."""
    server = xmlrpc.server.SimpleXMLRPCServer(("0.0.0.0", 8000))  # bind-all-interfaces
    # Registering os.system as RPC method — RCE
    server.register_function(os.system, "run_command")  # os-system exposed via RPC
    server.register_function(eval, "evaluate")  # eval exposed via RPC
    server.register_introspection_functions()
    return server


def xmlrpc_client_ssrf(url: str, method: str, *args):
    """XML-RPC client — SSRF via user-controlled URL."""
    proxy = xmlrpc.client.ServerProxy(url)  # ssrf-risk — user controls URL
    func = getattr(proxy, method)
    return func(*args)


# ── Section 4: ctypes advanced patterns ──────────────────────────────

def ctypes_cdll_direct(lib_path: str):
    """Load shared library directly via CDLL constructor."""
    lib = ctypes.CDLL(lib_path)  # arbitrary code execution via shared library
    return lib


def ctypes_windll_direct(lib_name: str):
    """Load Windows DLL directly."""
    lib = ctypes.WinDLL(lib_name)  # arbitrary code execution via DLL
    return lib


def ctypes_pointer_cast(addr: int):
    """Cast integer to pointer — memory corruption risk."""
    ptr = ctypes.cast(addr, ctypes.POINTER(ctypes.c_char))  # arbitrary memory access
    return ptr[0]


def ctypes_memmove_arbitrary(src: int, dst: int, size: int):
    """memmove with arbitrary addresses — memory corruption."""
    ctypes.memmove(dst, src, size)  # arbitrary memory write


# ── Section 5: Signal handler races ──────────────────────────────────

shared_state = {"count": 0, "data": None}


def unsafe_signal_handler(signum, frame):
    """Signal handler modifying shared state — race condition."""
    shared_state["count"] += 1  # non-atomic increment in signal handler
    conn = sqlite3.connect("app.db")
    conn.execute(f"INSERT INTO signals (sig) VALUES ({signum})")  # sql-injection in signal handler
    conn.commit()
    conn.close()


def setup_signal_handlers():
    """Install signal handlers with race conditions."""
    signal.signal(signal.SIGTERM, unsafe_signal_handler)
    signal.signal(signal.SIGINT, unsafe_signal_handler)


# ── Section 6: multiprocessing shared state ──────────────────────────

def worker_process(shared_dict, user_input: str):
    """Worker that uses shared dict unsafely."""
    # SQL injection in worker process
    conn = sqlite3.connect("shared.db")
    conn.execute(f"SELECT * FROM jobs WHERE id = '{user_input}'")  # sql-injection

    # eval in worker
    if "expr" in shared_dict:
        result = eval(shared_dict["expr"])  # eval-usage in worker
        shared_dict["result"] = result


def spawn_workers(tasks: list):
    """Spawn worker processes with shared state."""
    manager = multiprocessing.Manager()
    shared = manager.dict()

    for task in tasks:
        p = multiprocessing.Process(
            target=worker_process,
            args=(shared, task),
        )
        p.start()


# ── Section 7: tempfile advanced misuse ──────────────────────────────

def tempfile_predictable_name(prefix: str, data: str):
    """Create temp file with predictable name pattern."""
    path = os.path.join(tempfile.gettempdir(), f"{prefix}_{os.getpid()}.tmp")
    # Predictable: uses PID which is guessable
    with open(path, "w") as f:
        f.write(data)
    return path


def tempfile_world_readable(data: bytes):
    """Create temp file with insecure permissions."""
    fd, path = tempfile.mkstemp()
    os.chmod(path, 0o666)  # insecure-file-permissions — world-writable
    os.write(fd, data)
    os.close(fd)
    return path


def tempfile_no_cleanup(data: str):
    """Create named temp file without cleanup."""
    f = tempfile.NamedTemporaryFile(delete=False, mode="w")  # no cleanup
    f.write(data)
    f.close()
    # File persists with potentially sensitive data
    return f.name


# ── Section 8: Logging configuration injection ──────────────────────

def setup_logging_from_dict(config: dict):
    """Configure logging from user-provided dict."""
    logging.config.dictConfig(config)  # can load arbitrary handlers/formatters


def setup_logging_from_file(config_path: str):
    """Configure logging from user-provided file path."""
    logging.config.fileConfig(config_path)  # path traversal + arbitrary config


def log_with_user_format(message: str, fmt: str):
    """Log with user-controlled format string."""
    # Format string injection — user controls the format
    logger.info(fmt % message)  # if fmt has %s%s%s... → crash or info leak


# ── Section 9: struct pack/unpack issues ─────────────────────────────

def parse_binary_header(data: bytes):
    """Parse untrusted binary data — buffer overflow risk."""
    if len(data) < 4:
        return None
    size = struct.unpack("!I", data[:4])[0]  # size from untrusted data
    # No bounds check — could be huge
    payload = data[4:4 + size]  # potential memory exhaustion
    return payload


def parse_network_packet(data: bytes):
    """Parse network packet with user-controlled format."""
    # If format comes from config/user, arbitrary memory read
    fmt = "!" + "I" * (len(data) // 4)
    return struct.unpack(fmt, data[:struct.calcsize(fmt)])


# ── Section 10: code module — interactive interpreter ────────────────

def start_debug_console(local_vars: dict):
    """Start interactive console — RCE."""
    console = code.InteractiveConsole(locals=local_vars)
    console.interact()  # full Python interpreter access


def compile_and_exec(source: str, filename: str = "<user>"):
    """Compile and exec user code."""
    compiled = compile(source, filename, "exec")  # compile-usage
    exec(compiled)  # exec-usage


def run_code_object(code_bytes: bytes):
    """Execute marshalled code object."""
    code_obj = marshal.loads(code_bytes)  # unsafe-deserialization
    exec(code_obj)  # exec-usage — RCE via marshalled code


# ── Section 11: CGI remnants ─────────────────────────────────────────

def handle_cgi_form():
    """CGI form handling — multiple vulnerabilities."""
    form = cgi.FieldStorage()
    username = form.getvalue("username", "")
    query = form.getvalue("query", "")

    # SQL injection from CGI input
    conn = sqlite3.connect("app.db")
    conn.execute(f"SELECT * FROM users WHERE username = '{username}'")  # sql-injection

    # Command injection from CGI input
    os.system(f"grep -r {query} /var/log/")  # os-system with user input

    # eval from CGI input
    if "calc" in form:
        result = eval(form.getvalue("calc"))  # eval-usage


# ── Section 12: Platform/sysconfig info leaks ────────────────────────

def system_info_endpoint():
    """Endpoint returning system information — info disclosure."""
    return {
        "platform": platform.platform(),
        "python": platform.python_version(),
        "node": platform.node(),  # hostname leak
        "arch": platform.architecture(),
        "processor": platform.processor(),
        "uname": str(platform.uname()),  # full system info
        "paths": {
            "prefix": sysconfig.get_path("purelib"),
            "scripts": sysconfig.get_path("scripts"),
        },
        "env": dict(os.environ),  # full environment leak including secrets
    }


# ── Section 13: Cookie manipulation ──────────────────────────────────

def set_insecure_cookie(response_headers: list, name: str, value: str):
    """Set cookie without security flags."""
    cookie = http.cookies.SimpleCookie()
    cookie[name] = value
    # Missing: Secure, HttpOnly, SameSite flags
    response_headers.append(("Set-Cookie", cookie.output(header="")))


def parse_cookie_eval(cookie_header: str):
    """Parse cookie and eval its value — RCE."""
    cookie = http.cookies.SimpleCookie(cookie_header)
    for key in cookie:
        val = cookie[key].value
        if key == "config":
            return eval(val)  # eval-usage — RCE via cookie value
    return None


# ── Section 14: Aliased import — fromstring XXE ─────────────────────

def parse_xml_response(xml_string: str):
    """Parse XML from aliased import at top of file."""
    root = xml_from_str(xml_string)  # xxe-risk via 'from ... import fromstring as xml_from_str'
    return {child.tag: child.text for child in root}


def parse_xml_with_entity(xml_data: str):
    """Parse XML that may contain entity expansion."""
    # Billion laughs / entity expansion attack
    root = xml_from_str(xml_data)  # xxe-risk — same aliased import
    return root


# ── Section 15: Weak crypto patterns not yet covered ─────────────────

def xor_encrypt(data: bytes, key: bytes) -> bytes:
    """XOR 'encryption' — trivially reversible."""
    return bytes(a ^ b for a, b in zip(data, key * (len(data) // len(key) + 1)))


def rot13_hash(password: str) -> str:
    """ROT13 as 'hashing' — reversible."""
    import codecs
    return codecs.encode(password, "rot_13")


def crc32_integrity(data: bytes) -> int:
    """CRC32 for integrity — trivially forgeable."""
    import binascii
    return binascii.crc32(data)


def compare_hashes_insecure(hash1: str, hash2: str) -> bool:
    """String comparison for hash verification — timing attack."""
    return hash1 == hash2  # timing attack


# ── Section 16: os.environ as secret storage ─────────────────────────

def log_environment():
    """Log all environment variables — leaks secrets."""
    for key, value in os.environ.items():
        logger.info(f"ENV: {key}={value}")  # logging-sensitive-data — env may contain secrets


def env_to_sql(conn, env_key: str):
    """Use env var directly in SQL."""
    value = os.environ.get(env_key, "default")
    conn.execute(f"INSERT INTO config (key, value) VALUES ('{env_key}', '{value}')")  # sql-injection


# ── Section 17: subprocess with untrusted env vars ───────────────────

def subprocess_with_ld_preload(cmd: list, preload_lib: str):
    """Subprocess with LD_PRELOAD — library injection."""
    env = os.environ.copy()
    env["LD_PRELOAD"] = preload_lib  # env-path-injection — arbitrary library injection
    return subprocess.run(cmd, env=env)


def subprocess_path_override(cmd: str, custom_path: str):
    """Subprocess with overridden PATH — command hijacking."""
    env = os.environ.copy()
    env["PATH"] = custom_path + ":" + env.get("PATH", "")  # env-path-injection
    return subprocess.run(cmd, shell=True, env=env)  # shell-true + PATH hijacking


# ── Section 18: Server binding patterns ──────────────────────────────

def bind_socket_all_interfaces(port: int):
    """Socket binding to all interfaces."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", port))  # bind-all-interfaces
    s.listen(5)
    return s


def bind_udp_all(port: int):
    """UDP socket on all interfaces."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("0.0.0.0", port))  # bind-all-interfaces
    return s


def create_ssl_server_no_verify(port: int, certfile: str):
    """SSL server with no client verification."""
    import ssl
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile)
    # Missing: context.verify_mode = ssl.CERT_REQUIRED
    # Missing: context.load_verify_locations(ca_cert)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("0.0.0.0", port))  # bind-all-interfaces
    ssl_sock = context.wrap_socket(sock, server_side=True)
    return ssl_sock


# ── Section 19: Chained vulnerability — config to RCE ───────────────

def load_plugin(plugin_path: str):
    """Load plugin from path — arbitrary code execution."""
    import importlib.util
    spec = importlib.util.spec_from_file_location("plugin", plugin_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)  # exec arbitrary Python file
    return module


def config_driven_rce(config: dict):
    """Config-driven execution — multiple RCE paths."""
    # Path 1: eval from config
    if "formula" in config:
        result = eval(config["formula"])  # eval-usage

    # Path 2: os.system from config
    if "post_hook" in config:
        os.system(config["post_hook"])  # os-system

    # Path 3: pickle from config-specified file
    if "cache_file" in config:
        with open(config["cache_file"], "rb") as f:
            data = pickle.load(f)  # pickle-unsafe

    # Path 4: subprocess from config
    if "command" in config:
        subprocess.run(config["command"], shell=True)  # shell-true


# ── Section 20: Timing-sensitive comparisons ─────────────────────────

def verify_api_key(provided: str, stored: str) -> bool:
    """API key verification with timing leak."""
    return provided == stored  # timing attack on API key


def verify_signature(message: bytes, sig: bytes, key: bytes) -> bool:
    """HMAC signature verification with timing leak."""
    expected = hmac.new(key, message, hashlib.sha256).digest()
    return sig == expected  # timing attack on HMAC


def verify_token_length_leak(token: str, expected: str) -> bool:
    """Token verification that leaks length."""
    if len(token) != len(expected):
        return False  # early return leaks length
    for a, b in zip(token, expected):
        if a != b:
            return False  # character-by-character timing leak
    return True
