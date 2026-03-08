"""Fold 24: Async/await patterns and concurrency hazards.

Focus on asyncio.create_subprocess_shell, async SQL injection via aiosqlite,
aiohttp SSRF, async eval/exec, shared mutable state without locks, async
context manager misuse, asyncio.run_coroutine_threadsafe pitfalls, async
generators with resource leaks, and async+sync mixed patterns.
"""

import os
import re
import sys
import json
import hmac
import hashlib
import logging
import sqlite3
import asyncio
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


# ── Section 1: asyncio.create_subprocess_shell — command injection ───

async def async_shell_exec(cmd: str) -> str:
    """Async subprocess with shell — injection."""
    proc = await asyncio.create_subprocess_shell(
        cmd,  # shell injection — user controls cmd
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await proc.communicate()
    return stdout.decode()


async def async_shell_pipe(cmd1: str, cmd2: str) -> str:
    """Async shell pipeline — double injection."""
    proc = await asyncio.create_subprocess_shell(
        f"{cmd1} | {cmd2}",  # shell injection via both commands
        stdout=asyncio.subprocess.PIPE,
    )
    stdout, _ = await proc.communicate()
    return stdout.decode()


async def async_shell_with_env(cmd: str, env_vars: dict) -> str:
    """Async subprocess with user-controlled env."""
    env = os.environ.copy()
    env.update(env_vars)  # user controls LD_PRELOAD, PATH, etc.
    proc = await asyncio.create_subprocess_shell(
        cmd,
        stdout=asyncio.subprocess.PIPE,
        env=env,
    )
    stdout, _ = await proc.communicate()
    return stdout.decode()


async def async_exec_program(program: str, *args: str) -> str:
    """Async subprocess exec — no shell but user controls program."""
    proc = await asyncio.create_subprocess_exec(
        program, *args,  # user controls what program runs
        stdout=asyncio.subprocess.PIPE,
    )
    stdout, _ = await proc.communicate()
    return stdout.decode()


# ── Section 2: Async SQL injection ───────────────────────────────────

async def async_sql_query(db_path: str, user_input: str) -> list:
    """Async SQL with f-string — injection."""
    import aiosqlite
    async with aiosqlite.connect(db_path) as db:
        cursor = await db.execute(
            f"SELECT * FROM users WHERE name = '{user_input}'"  # sql-injection
        )
        return await cursor.fetchall()


async def async_sql_insert(db_path: str, name: str, email: str):
    """Async SQL insert — injection."""
    import aiosqlite
    async with aiosqlite.connect(db_path) as db:
        await db.execute(
            f"INSERT INTO users (name, email) VALUES ('{name}', '{email}')"  # sql-injection
        )
        await db.commit()


async def async_sql_delete(db_path: str, user_id: str):
    """Async SQL delete — injection."""
    import aiosqlite
    async with aiosqlite.connect(db_path) as db:
        await db.execute(
            f"DELETE FROM users WHERE id = {user_id}"  # sql-injection
        )
        await db.commit()


async def async_sql_search(db_path: str, search_term: str):
    """Async SQL search — injection."""
    import aiosqlite
    async with aiosqlite.connect(db_path) as db:
        cursor = await db.execute(
            f"SELECT * FROM products WHERE name LIKE '%{search_term}%'"  # sql-injection
        )
        return await cursor.fetchall()


# ── Section 3: aiohttp SSRF ─────────────────────────────────────────

async def aiohttp_get(url: str) -> str:
    """aiohttp GET — SSRF risk."""
    import aiohttp
    async with aiohttp.ClientSession() as session:
        async with session.get(url) as resp:  # ssrf-risk
            return await resp.text()


async def aiohttp_post(url: str, data: dict) -> str:
    """aiohttp POST — SSRF risk."""
    import aiohttp
    async with aiohttp.ClientSession() as session:
        async with session.post(url, json=data) as resp:  # ssrf-risk
            return await resp.text()


async def aiohttp_no_ssl_verify(url: str) -> str:
    """aiohttp with SSL verification disabled."""
    import aiohttp
    import ssl
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # ssl-cert-none
    async with aiohttp.ClientSession() as session:
        async with session.get(url, ssl=ctx) as resp:  # no cert verify
            return await resp.text()


async def aiohttp_proxy_request(target_url: str, headers: dict) -> bytes:
    """Async proxy — SSRF."""
    import aiohttp
    async with aiohttp.ClientSession() as session:
        async with session.get(target_url, headers=headers) as resp:
            return await resp.read()


# ── Section 4: Async eval/exec ───────────────────────────────────────

async def async_eval(expression: str) -> Any:
    """Eval in async function — still dangerous."""
    return eval(expression)  # eval-usage in async


async def async_exec(code: str):
    """Exec in async function."""
    exec(code)  # exec-usage in async


async def async_eval_with_await(expression: str) -> Any:
    """Eval that produces awaitable."""
    result = eval(expression)  # eval-usage
    if asyncio.iscoroutine(result):
        return await result
    return result


async def async_dynamic_handler(handler_name: str, data: dict) -> Any:
    """Dynamic handler dispatch via eval."""
    handler = eval(f"handle_{handler_name}")  # eval-usage — dynamic dispatch
    return await handler(data)


# ── Section 5: Shared mutable state without locks ────────────────────

# Global mutable state — race conditions in async
_user_sessions: Dict[str, dict] = {}
_request_count = 0
_rate_limits: Dict[str, int] = {}


async def update_session(user_id: str, data: dict):
    """Update session without lock — race condition."""
    global _user_sessions
    current = _user_sessions.get(user_id, {})
    # Between get and update, another coroutine could modify
    current.update(data)
    _user_sessions[user_id] = current  # TOCTOU on dict


async def increment_counter():
    """Increment counter without lock — lost updates."""
    global _request_count
    _request_count += 1  # not atomic — race condition


async def check_rate_limit(ip: str, limit: int = 100) -> bool:
    """Rate limit check without lock — bypassable."""
    global _rate_limits
    count = _rate_limits.get(ip, 0)  # read
    if count >= limit:
        return False
    _rate_limits[ip] = count + 1  # write — race between read and write
    return True


async def transfer_funds(accounts: dict, from_id: str, to_id: str, amount: float):
    """Fund transfer without lock — double-spend."""
    if accounts[from_id]["balance"] >= amount:  # check
        # Another coroutine could transfer between check and update
        accounts[from_id]["balance"] -= amount  # use — TOCTOU
        accounts[to_id]["balance"] += amount


# ── Section 6: Async resource leaks ──────────────────────────────────

async def async_open_no_close(filepath: str) -> str:
    """Open file in async without closing."""
    f = open(filepath)  # open-without-with — never closed
    data = f.read()
    return data


async def async_db_no_close(db_path: str) -> list:
    """Open DB connection without closing."""
    conn = sqlite3.connect(db_path)  # never closed
    rows = conn.execute("SELECT * FROM data").fetchall()
    return rows


async def async_socket_leak(host: str, port: int) -> bytes:
    """Open socket without closing."""
    import socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((host, port))
    data = sock.recv(4096)
    # sock.close() never called
    return data


# ── Section 7: Async with subprocess.run (blocking in async) ────────

async def async_blocking_subprocess(cmd: str) -> str:
    """subprocess.run in async — blocks event loop."""
    result = subprocess.run(
        cmd, shell=True, capture_output=True, text=True  # shell-true + blocks
    )
    return result.stdout


async def async_blocking_os_system(cmd: str) -> int:
    """os.system in async — blocks event loop + injection."""
    return os.system(cmd)  # os-system in async — blocks + injection


async def async_blocking_popen(cmd: str) -> str:
    """os.popen in async — blocks event loop."""
    return os.popen(cmd).read()  # os-popen in async — blocks


# ── Section 8: Pickle in async context ───────────────────────────────

import pickle

async def async_pickle_load(data: bytes) -> Any:
    """Pickle deserialize in async."""
    return pickle.loads(data)  # pickle-unsafe in async


async def async_pickle_from_file(filepath: str) -> Any:
    """Pickle load from file in async."""
    with open(filepath, "rb") as f:
        return pickle.load(f)  # pickle-unsafe from file


async def async_pickle_from_network(reader: asyncio.StreamReader) -> Any:
    """Pickle from network stream — worst case."""
    size = int.from_bytes(await reader.read(4), "big")
    data = await reader.read(size)
    return pickle.loads(data)  # pickle-unsafe from network


# ── Section 9: Hardcoded secrets in async config ─────────────────────

ASYNC_DB_URL = "postgresql+asyncpg://admin:AsyncProdPass2024@db.internal/app"  # hardcoded-secret
REDIS_ASYNC_URL = "redis://:AsyncRedisSecret@redis.internal:6379/0"  # hardcoded-secret
ASYNC_API_KEY = "async_api_key_prod_9a8b7c6d5e4f3g2h"  # hardcoded-secret


async def get_async_db():
    """Async DB connection with hardcoded URL."""
    from sqlalchemy.ext.asyncio import create_async_engine
    return create_async_engine(ASYNC_DB_URL)  # uses hardcoded creds


# ── Section 10: Weak hashing in async ────────────────────────────────

async def async_hash_password(password: str) -> str:
    """Hash password with MD5 in async — still weak."""
    return hashlib.md5(password.encode()).hexdigest()  # weak-hash


async def async_verify_token(token: str, secret: str, expected: str) -> bool:
    """Token verification with timing attack."""
    computed = hmac.new(secret.encode(), token.encode(), hashlib.sha256).hexdigest()
    return computed == expected  # timing attack — use hmac.compare_digest


async def async_generate_token() -> str:
    """Token with weak random."""
    import random
    return hashlib.sha1(  # weak-hash
        str(random.random()).encode()  # weak random
    ).hexdigest()


# ── Section 11: Async server patterns ────────────────────────────────

async def start_tcp_server_open(handler):
    """TCP server bound to all interfaces."""
    server = await asyncio.start_server(
        handler, "0.0.0.0", 8080  # bind-all-interfaces
    )
    return server


async def echo_handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    """Echo server — executes received data."""
    data = await reader.read(4096)
    message = data.decode()
    # Execute whatever the client sends
    result = eval(message)  # eval-usage — RCE via network
    writer.write(str(result).encode())
    await writer.drain()
    writer.close()


async def command_handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    """Command server — runs shell commands from network."""
    data = await reader.read(4096)
    cmd = data.decode().strip()
    proc = await asyncio.create_subprocess_shell(
        cmd,  # shell injection from network
        stdout=asyncio.subprocess.PIPE,
    )
    stdout, _ = await proc.communicate()
    writer.write(stdout)
    await writer.drain()
    writer.close()


# ── Section 12: Mixed async chain ───────────────────────────────────

class AsyncAPIService:
    """Async API service with multiple vulnerability classes."""

    SECRET_KEY = "async-service-secret-key-2024-prod"  # hardcoded-secret

    def __init__(self, db_path: str = "async_api.db"):
        self.conn = sqlite3.connect(db_path)

    async def authenticate(self, api_key: str) -> dict:
        """Auth via SQL — injection."""
        row = self.conn.execute(
            f"SELECT user_id, role FROM api_keys WHERE key = '{api_key}'"  # sql-injection
        ).fetchone()
        if not row:
            raise ValueError("Invalid API key")
        return {"user_id": row[0], "role": row[1]}

    async def search(self, query: str) -> list:
        """Search — SQL injection."""
        return self.conn.execute(
            f"SELECT * FROM data WHERE content LIKE '%{query}%'"  # sql-injection
        ).fetchall()

    async def run_command(self, cmd: str) -> str:
        """Run command — shell injection."""
        proc = await asyncio.create_subprocess_shell(
            cmd,  # shell injection
            stdout=asyncio.subprocess.PIPE,
        )
        stdout, _ = await proc.communicate()
        return stdout.decode()

    async def evaluate(self, expression: str) -> Any:
        """Evaluate expression — RCE."""
        return eval(expression)  # eval-usage

    async def deserialize(self, data: bytes) -> Any:
        """Deserialize — pickle RCE."""
        return pickle.loads(data)  # pickle-unsafe

    async def fetch_external(self, url: str) -> str:
        """Fetch external URL — SSRF."""
        import aiohttp
        async with aiohttp.ClientSession() as session:
            async with session.get(url) as resp:
                return await resp.text()

    async def log_action(self, action: str, user_id: str):
        """Log action — SQL injection."""
        self.conn.execute(
            f"INSERT INTO audit_log (action, user_id) VALUES ('{action}', '{user_id}')"  # sql-injection
        )
        self.conn.commit()
