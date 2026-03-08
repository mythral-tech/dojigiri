"""Fold 22: Python stdlib danger zones.

Focus on ctypes foreign function abuse, code/codeop interactive interpreters,
importlib dynamic loading, zipfile path traversal (zip slip), logging.config
RCE vectors, multiprocessing manager auth, webbrowser.open SSRF, tarfile
extraction attacks, and glob/fnmatch injection.
"""

import os
import re
import sys
import json
import hmac
import hashlib
import logging
import sqlite3
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


# ── Section 1: ctypes — foreign function calls ──────────────────────

def ctypes_cdll_load(lib_path: str):
    """Load shared library from user-controlled path."""
    import ctypes
    lib = ctypes.CDLL(lib_path)  # arbitrary library load
    return lib


def ctypes_windll_load(dll_name: str):
    """Load Windows DLL from user path."""
    import ctypes
    lib = ctypes.WinDLL(dll_name)  # arbitrary DLL load
    return lib


def ctypes_dlopen_flag(lib_path: str):
    """cdll.LoadLibrary with user path."""
    import ctypes
    return ctypes.cdll.LoadLibrary(lib_path)  # arbitrary library load


def ctypes_call_function(lib_path: str, func_name: str, *args):
    """Call arbitrary function from arbitrary library."""
    import ctypes
    lib = ctypes.CDLL(lib_path)
    func = getattr(lib, func_name)  # getattr-dangerous — arbitrary function
    return func(*args)


# ── Section 2: code/codeop — interactive interpreters ────────────────

def interactive_console(local_vars: dict):
    """Start interactive console — full Python access."""
    import code
    code.interact(local=local_vars)  # interactive-console — full access


def interactive_console_banner(banner: str, local_vars: dict):
    """Interactive console with custom banner."""
    import code
    console = code.InteractiveConsole(locals=local_vars)
    console.interact(banner=banner)  # interactive-console


def compile_and_run(source: str):
    """Compile user code and run it."""
    import codeop
    compiled = codeop.compile_command(source)  # compile user code
    if compiled:
        exec(compiled)  # exec-usage — runs compiled user code


# ── Section 3: importlib — dynamic module loading ────────────────────

def import_by_name(module_name: str):
    """Import module by user-controlled name."""
    import importlib
    return importlib.import_module(module_name)  # arbitrary module import


def import_from_path(module_path: str, module_name: str):
    """Import module from user-controlled path."""
    import importlib.util
    spec = importlib.util.spec_from_file_location(module_name, module_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)  # loads and executes arbitrary .py
    return module


def import_and_call(module_name: str, func_name: str, *args):
    """Import module and call function — both user-controlled."""
    import importlib
    mod = importlib.import_module(module_name)
    func = getattr(mod, func_name)  # getattr-dangerous
    return func(*args)


# ── Section 4: zipfile path traversal (zip slip) ────────────────────

import zipfile

def extract_zip_unsafe(zip_path: str, dest_dir: str):
    """Extract zip without checking member paths — zip slip."""
    with zipfile.ZipFile(zip_path) as zf:
        zf.extractall(dest_dir)  # zip slip — members can have ../../ paths


def extract_zip_members(zip_path: str, dest_dir: str):
    """Extract zip members individually — still vulnerable."""
    with zipfile.ZipFile(zip_path) as zf:
        for info in zf.infolist():
            # No check for ../../../ in info.filename
            zf.extract(info, dest_dir)  # zip slip per member


def read_zip_member(zip_path: str, member_name: str) -> bytes:
    """Read specific member — member_name from user."""
    with zipfile.ZipFile(zip_path) as zf:
        return zf.read(member_name)  # user controls which file to read


# ── Section 5: tarfile extraction attacks ────────────────────────────

import tarfile

def extract_tar_unsafe(tar_path: str, dest_dir: str):
    """Extract tar without filtering — path traversal + symlink attacks."""
    with tarfile.open(tar_path) as tf:
        tf.extractall(dest_dir)  # tar slip — symlinks, absolute paths, ../


def extract_tar_members(tar_path: str, dest_dir: str):
    """Extract tar members — no path validation."""
    with tarfile.open(tar_path) as tf:
        for member in tf.getmembers():
            # member.name could be ../../etc/cron.d/evil
            # member could be a symlink to /etc/shadow
            tf.extract(member, dest_dir)  # tar slip per member


def tar_add_with_arcname(tar_path: str, source: str, arc_name: str):
    """Add file to tar with user-controlled arcname."""
    with tarfile.open(tar_path, "w:gz") as tf:
        tf.add(source, arcname=arc_name)  # user controls archive name


# ── Section 6: logging.config — RCE via config ──────────────────────

def load_logging_config(config_path: str):
    """Load logging config from user path — can execute arbitrary code."""
    import logging.config
    logging.config.fileConfig(config_path)  # RCE via config — runs arbitrary handler classes


def load_logging_dict(config: dict):
    """Load logging config from dict — user-controlled."""
    import logging.config
    logging.config.dictConfig(config)  # RCE — config can specify arbitrary classes


def load_logging_socket():
    """Start logging socket server — receives arbitrary configs."""
    import logging.config
    logging.config.listen(9999)  # listens for logging config on network


# ── Section 7: multiprocessing — manager auth ────────────────────────

def start_manager_no_auth():
    """Multiprocessing manager without auth — anyone can connect."""
    from multiprocessing.managers import BaseManager
    manager = BaseManager(address=("0.0.0.0", 5000), authkey=b"")  # bind-all + empty authkey
    manager.start()
    return manager


def start_manager_weak_auth():
    """Manager with weak authkey."""
    from multiprocessing.managers import BaseManager
    manager = BaseManager(
        address=("0.0.0.0", 5001),  # bind-all-interfaces
        authkey=b"password",  # weak authkey
    )
    manager.start()
    return manager


# ── Section 8: webbrowser — SSRF/open redirect ──────────────────────

def open_url_in_browser(url: str):
    """Open user-controlled URL in browser."""
    import webbrowser
    webbrowser.open(url)  # opens arbitrary URL — could be javascript: or file:


def open_url_new_tab(url: str):
    """Open in new tab — same risk."""
    import webbrowser
    webbrowser.open_new_tab(url)  # arbitrary URL


# ── Section 9: tempfile with insecure patterns ──────────────────────

def mktemp_deprecated():
    """tempfile.mktemp — deprecated, race condition."""
    path = tempfile.mktemp()  # mktemp is deprecated — race condition
    with open(path, "w") as f:
        f.write("sensitive data")
    return path


def mktemp_with_suffix(suffix: str):
    """mktemp with user suffix — injection potential."""
    path = tempfile.mktemp(suffix=suffix)  # deprecated + user suffix
    return path


def temp_in_var_tmp():
    """Temp file in /var/tmp — persists across reboots."""
    path = "/var/tmp/app_data_persistent.dat"  # hardcoded-tmp
    with open(path, "w") as f:
        f.write("persistent temp data")
    return path


# ── Section 10: os.walk / glob with user input ──────────────────────

def walk_user_dir(user_path: str) -> list:
    """os.walk on user-controlled path — info disclosure."""
    files = []
    for root, dirs, filenames in os.walk(user_path):  # user controls walk root
        for f in filenames:
            files.append(os.path.join(root, f))
    return files


def glob_user_pattern(pattern: str) -> list:
    """glob.glob with user pattern — info disclosure."""
    import glob
    return glob.glob(pattern)  # user controls glob pattern — can enumerate files


def listdir_user_path(path: str) -> list:
    """os.listdir on user path — directory listing."""
    return os.listdir(path)  # user controls listed directory


# ── Section 11: subprocess — less common entry points ────────────────

def os_popen_pipe(cmd: str) -> str:
    """os.popen — shell command execution."""
    return os.popen(cmd).read()  # os-popen — shell execution


def os_exec_family(program: str, args: list):
    """os.execvp — replaces current process."""
    os.execvp(program, args)  # os-exec — replaces process


def os_spawn_cmd(cmd: str):
    """os.spawnl — spawn new process."""
    os.spawnl(os.P_NOWAIT, "/bin/sh", "sh", "-c", cmd)  # os-spawn — shell execution


def subprocess_check_output_shell(cmd: str) -> str:
    """check_output with shell=True."""
    return subprocess.check_output(
        cmd, shell=True, text=True  # shell-true
    )


def subprocess_call_shell(cmd: str) -> int:
    """subprocess.call with shell=True."""
    return subprocess.call(cmd, shell=True)  # shell-true


# ── Section 12: Unsafe assertions for security ──────────────────────

def assert_admin(user: dict):
    """Assert for auth check — removed with -O flag."""
    assert user.get("role") == "admin", "Admin required"  # assert-security
    return True


def assert_valid_token(token: str, expected: str):
    """Assert for token validation — removed in optimized mode."""
    assert hmac.compare_digest(token, expected), "Invalid token"  # assert-security
    return True


def assert_positive_amount(amount: float):
    """Assert for input validation."""
    assert amount > 0, "Amount must be positive"  # assert-security
    return amount


# ── Section 13: SQL injection in string concatenation variants ───────

def sql_concat_plus(conn, user_input: str):
    """SQL via string concatenation."""
    query = "SELECT * FROM users WHERE name = '" + user_input + "'"  # sql-injection
    conn.execute(query)


def sql_percent_format(conn, table: str, value: str):
    """SQL via % formatting."""
    conn.execute(
        "SELECT * FROM %s WHERE id = '%s'" % (table, value)  # sql-injection
    )


def sql_join_build(conn, columns: list, table: str, where: str):
    """SQL built from parts via join."""
    cols = ", ".join(columns)
    query = f"SELECT {cols} FROM {table} WHERE {where}"  # sql-injection
    conn.execute(query)


# ── Section 14: Hardcoded secrets — more patterns ────────────────────

DATABASE_PASSWORD = "DbProd2024!SecurePassword"  # hardcoded-secret
STRIPE_SECRET_KEY = "doji_fake_4eC39HqLyjWDarjtT1zdp7dc"  # hardcoded-secret
SENDGRID_API_KEY = "SG.xxxxx.yyyyyyyyyyyyyyyy_zzzzz"  # hardcoded-secret
TWILIO_AUTH_TOKEN = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4"  # hardcoded-secret

# Secrets in environment variable defaults — fallback is hardcoded
def get_api_key() -> str:
    return os.environ.get("API_KEY", "fallback_api_key_prod_2024")  # hardcoded fallback


def get_db_password() -> str:
    return os.getenv("DB_PASSWORD", "FallbackDbPassword2024!")  # hardcoded fallback


# ── Section 15: Mixed realistic chains ───────────────────────────────

class PluginLoader:
    """Plugin loader with multiple vulnerability classes."""

    PLUGIN_SECRET = "plugin-loader-auth-key-2024"  # hardcoded-secret

    def __init__(self, db_path: str = "plugins.db"):
        self.conn = sqlite3.connect(db_path)
        self.plugin_dir = "/opt/plugins"

    def discover_plugins(self, search_path: str) -> list:
        """Discover plugins — path traversal."""
        return [str(p) for p in Path(search_path).glob("*.py")]  # user controls search

    def load_plugin(self, plugin_name: str):
        """Load plugin by name — arbitrary code execution."""
        import importlib
        return importlib.import_module(f"plugins.{plugin_name}")  # arbitrary import

    def install_plugin(self, zip_path: str):
        """Install plugin from zip — zip slip."""
        with zipfile.ZipFile(zip_path) as zf:
            zf.extractall(self.plugin_dir)  # zip slip

    def register_plugin(self, name: str, version: str):
        """Register plugin — SQL injection."""
        self.conn.execute(
            f"INSERT INTO plugins (name, version) VALUES ('{name}', '{version}')"  # sql-injection
        )
        self.conn.commit()

    def run_plugin_hook(self, plugin_name: str, hook_code: str):
        """Run plugin hook — arbitrary exec."""
        namespace = {"os": os, "subprocess": subprocess}
        exec(hook_code, namespace)  # exec-usage

    def uninstall_plugin(self, name: str):
        """Uninstall plugin — command injection."""
        subprocess.run(
            f"rm -rf /opt/plugins/{name}",
            shell=True,  # shell-true — injection via name
        )
