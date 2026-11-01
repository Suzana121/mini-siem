"""Users, sessions, API keys and the FastAPI dependencies that enforce them.

Security notes:
- Passwords are hashed with argon2id. Session tokens and API keys are random,
  high-entropy secrets; only their SHA-256 is stored, so a database leak does
  not yield usable credentials.
- Cookie-authenticated unsafe requests need the X-Requested-With header (CSRF).
- Login errors are identical for unknown user / wrong password / disabled user,
  and unknown users still pay for a dummy hash verification.
- Secrets (passwords, tokens, keys) are never logged.

Two stores share these semantics: PostgresAuthStore for real deployments,
MemoryAuthStore for tests and running without a database.
"""

import asyncio
import hashlib
import hmac
import itertools
import os
import re
import secrets
import time
from collections import deque
from datetime import datetime, timedelta, timezone
from typing import Literal, Protocol

import asyncpg
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from fastapi import HTTPException, Request
from pydantic import BaseModel, Field

Role = Literal["viewer", "analyst", "admin"]
ROLE_RANK: dict[str, int] = {"viewer": 1, "analyst": 2, "admin": 3}

SESSION_COOKIE = "session"
SESSION_TTL = timedelta(hours=12)
CSRF_HEADER = "x-requested-with"
CSRF_VALUE = "mini-siem"
API_KEY_PREFIX = "msk_"
MIN_PASSWORD_LENGTH = 12
MAX_PASSWORD_LENGTH = 256
USERNAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{2,63}$")
LOGIN_MAX_FAILURES = 5
LOGIN_WINDOW = timedelta(minutes=5)

_SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}


def _now() -> datetime:
    return datetime.now(timezone.utc)


# --- models -----------------------------------------------------------------


class User(BaseModel):
    id: str
    username: str
    role: Role
    disabled: bool = False
    created_at: datetime
    password_hash: str = Field(exclude=True, repr=False)


class ApiKey(BaseModel):
    """Metadata only: the secret is shown once at creation and never stored."""

    id: str
    name: str
    created_at: datetime


class DuplicateUserError(Exception):
    pass


class LastAdminError(Exception):
    """The change would leave no enabled admin."""


def normalize_username(username: str) -> str:
    return username.strip().lower()


def validate_username(username: str) -> str:
    if not USERNAME_RE.match(username):
        raise ValueError("username must be 3-64 chars of a-z, 0-9, '.', '_' or '-'")
    return username


def validate_password(password: str) -> str:
    if len(password) < MIN_PASSWORD_LENGTH:
        raise ValueError(f"password must be at least {MIN_PASSWORD_LENGTH} characters")
    if len(password) > MAX_PASSWORD_LENGTH:
        raise ValueError(f"password must be at most {MAX_PASSWORD_LENGTH} characters")
    return password


# --- hashing ----------------------------------------------------------------

_hasher = PasswordHasher()  # argon2id with library defaults
_dummy_hash: str | None = None


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(stored_hash: str, password: str) -> bool:
    try:
        return _hasher.verify(stored_hash, password)
    except (VerificationError, InvalidHashError):
        return False


async def hash_password_async(password: str) -> str:
    return await asyncio.to_thread(hash_password, password)


async def verify_password_async(stored_hash: str, password: str) -> bool:
    return await asyncio.to_thread(verify_password, stored_hash, password)


def dummy_hash() -> str:
    global _dummy_hash
    if _dummy_hash is None:
        _dummy_hash = hash_password(secrets.token_urlsafe(16))
    return _dummy_hash


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def new_session_token() -> str:
    return secrets.token_urlsafe(32)  # 32 random bytes


def new_api_key() -> str:
    return API_KEY_PREFIX + secrets.token_urlsafe(32)


# --- store ------------------------------------------------------------------


class AuthStore(Protocol):
    async def create_user(self, username: str, password_hash: str, role: Role) -> User:
        """Raises DuplicateUserError if the username is taken."""
        ...

    async def get_user(self, user_id: str) -> User | None: ...

    async def get_user_by_username(self, username: str) -> User | None: ...

    async def list_users(self) -> list[User]: ...

    async def count_users(self) -> int: ...

    async def update_user(
        self,
        user_id: str,
        *,
        role: Role | None = None,
        disabled: bool | None = None,
        password_hash: str | None = None,
    ) -> User | None:
        """Raises LastAdminError rather than leave no enabled admin. Disabling a user
        or changing their password revokes their sessions in the same operation."""
        ...

    async def create_session(self, user_id: str, token_hash: str, expires_at: datetime) -> None: ...

    async def get_session_user(self, token_hash: str) -> User | None:
        """The user for an unexpired session, else None."""
        ...

    async def delete_session(self, token_hash: str) -> None: ...

    async def revoke_user_sessions(self, user_id: str) -> int: ...

    async def create_api_key(self, name: str, key_hash: str) -> ApiKey: ...

    async def get_api_key_by_hash(self, key_hash: str) -> ApiKey | None: ...

    async def list_api_keys(self) -> list[ApiKey]: ...

    async def delete_api_key(self, key_id: str) -> bool: ...

    async def close(self) -> None: ...


def _new_id() -> str:
    return secrets.token_hex(8)


def _enabled_admin(role: str, disabled: bool) -> bool:
    return role == "admin" and not disabled


class MemoryAuthStore:
    def __init__(self):
        self._users: dict[str, User] = {}
        self._order = itertools.count()
        self._sessions: dict[str, tuple[str, datetime]] = {}  # token_hash -> (user_id, expires_at)
        self._keys: dict[str, tuple[ApiKey, str]] = {}  # id -> (key, key_hash)

    async def create_user(self, username, password_hash, role) -> User:
        if any(u.username == username for u in self._users.values()):
            raise DuplicateUserError(username)
        user = User(id=_new_id(), username=username, role=role, created_at=_now(), password_hash=password_hash)
        self._users[user.id] = user
        return user

    async def get_user(self, user_id) -> User | None:
        return self._users.get(user_id)

    async def get_user_by_username(self, username) -> User | None:
        return next((u for u in self._users.values() if u.username == username), None)

    async def list_users(self) -> list[User]:
        return sorted(self._users.values(), key=lambda u: (u.created_at, u.username))

    async def count_users(self) -> int:
        return len(self._users)

    async def update_user(self, user_id, *, role=None, disabled=None, password_hash=None) -> User | None:
        user = self._users.get(user_id)
        if user is None:
            return None
        new_role = role if role is not None else user.role
        new_disabled = disabled if disabled is not None else user.disabled
        if _enabled_admin(user.role, user.disabled) and not _enabled_admin(new_role, new_disabled):
            others = [u for u in self._users.values() if u.id != user.id and _enabled_admin(u.role, u.disabled)]
            if not others:
                raise LastAdminError()
        user.role, user.disabled = new_role, new_disabled
        if password_hash is not None:
            user.password_hash = password_hash
        if new_disabled or password_hash is not None:
            await self.revoke_user_sessions(user.id)
        return user

    async def create_session(self, user_id, token_hash, expires_at) -> None:
        self._sessions[token_hash] = (user_id, expires_at)

    async def get_session_user(self, token_hash) -> User | None:
        entry = self._sessions.get(token_hash)
        if entry is None:
            return None
        user_id, expires_at = entry
        if expires_at <= _now():
            self._sessions.pop(token_hash, None)
            return None
        return self._users.get(user_id)

    async def delete_session(self, token_hash) -> None:
        self._sessions.pop(token_hash, None)

    async def revoke_user_sessions(self, user_id) -> int:
        doomed = [h for h, (uid, _) in self._sessions.items() if uid == user_id]
        for h in doomed:
            del self._sessions[h]
        return len(doomed)

    async def create_api_key(self, name, key_hash) -> ApiKey:
        key = ApiKey(id=_new_id(), name=name, created_at=_now())
        self._keys[key.id] = (key, key_hash)
        return key

    async def get_api_key_by_hash(self, key_hash) -> ApiKey | None:
        for key, stored in self._keys.values():
            if hmac.compare_digest(stored, key_hash):
                return key
        return None

    async def list_api_keys(self) -> list[ApiKey]:
        return sorted((k for k, _ in self._keys.values()), key=lambda k: k.created_at)

    async def delete_api_key(self, key_id) -> bool:
        return self._keys.pop(key_id, None) is not None

    async def close(self) -> None:
        pass


SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id            TEXT PRIMARY KEY,
    username      TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL CHECK (role IN ('viewer', 'analyst', 'admin')),
    disabled      BOOLEAN NOT NULL DEFAULT FALSE,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,  -- SHA-256 of the cookie value
    user_id    TEXT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS sessions_user ON sessions (user_id);
CREATE INDEX IF NOT EXISTS sessions_expiry ON sessions (expires_at);
CREATE TABLE IF NOT EXISTS api_keys (
    id         TEXT PRIMARY KEY,
    name       TEXT NOT NULL,
    key_hash   TEXT NOT NULL UNIQUE,  -- SHA-256 of the key
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
"""

_USER_COLUMNS = "id, username, password_hash, role, disabled, created_at"


def _user(row) -> User | None:
    return User(**dict(row)) if row else None


def _api_key(row) -> ApiKey | None:
    return ApiKey(id=row["id"], name=row["name"], created_at=row["created_at"]) if row else None


class PostgresAuthStore:
    def __init__(self, pool: asyncpg.Pool):
        self._pool = pool

    @classmethod
    async def connect(cls, url: str) -> "PostgresAuthStore":
        pool = await asyncpg.create_pool(url, min_size=1, max_size=5)
        async with pool.acquire() as conn:
            await conn.execute(SCHEMA)
        return cls(pool)

    async def create_user(self, username, password_hash, role) -> User:
        try:
            row = await self._pool.fetchrow(
                f"INSERT INTO users (id, username, password_hash, role) VALUES ($1, $2, $3, $4) "
                f"RETURNING {_USER_COLUMNS}",
                _new_id(),
                username,
                password_hash,
                role,
            )
        except asyncpg.UniqueViolationError:
            raise DuplicateUserError(username) from None
        return _user(row)

    async def get_user(self, user_id) -> User | None:
        return _user(await self._pool.fetchrow(f"SELECT {_USER_COLUMNS} FROM users WHERE id = $1", user_id))

    async def get_user_by_username(self, username) -> User | None:
        return _user(await self._pool.fetchrow(f"SELECT {_USER_COLUMNS} FROM users WHERE username = $1", username))

    async def list_users(self) -> list[User]:
        rows = await self._pool.fetch(f"SELECT {_USER_COLUMNS} FROM users ORDER BY created_at, username")
        return [_user(r) for r in rows]

    async def count_users(self) -> int:
        return await self._pool.fetchval("SELECT count(*) FROM users")

    async def update_user(self, user_id, *, role=None, disabled=None, password_hash=None) -> User | None:
        async with self._pool.acquire() as conn, conn.transaction():
            # Lock every enabled admin (in a stable order) so concurrent demotions
            # cannot both pass the last-admin check.
            admins = {
                r["id"]
                for r in await conn.fetch(
                    "SELECT id FROM users WHERE role = 'admin' AND NOT disabled ORDER BY id FOR UPDATE"
                )
            }
            row = await conn.fetchrow(f"SELECT {_USER_COLUMNS} FROM users WHERE id = $1 FOR UPDATE", user_id)
            if row is None:
                return None
            new_role = role if role is not None else row["role"]
            new_disabled = disabled if disabled is not None else row["disabled"]
            if user_id in admins and not _enabled_admin(new_role, new_disabled) and len(admins) <= 1:
                raise LastAdminError()
            row = await conn.fetchrow(
                f"UPDATE users SET role = $2, disabled = $3, password_hash = COALESCE($4, password_hash) "
                f"WHERE id = $1 RETURNING {_USER_COLUMNS}",
                user_id,
                new_role,
                new_disabled,
                password_hash,
            )
            if new_disabled or password_hash is not None:
                await conn.execute("DELETE FROM sessions WHERE user_id = $1", user_id)
            return _user(row)

    async def create_session(self, user_id, token_hash, expires_at) -> None:
        await self._pool.execute("DELETE FROM sessions WHERE expires_at <= now()")
        await self._pool.execute(
            "INSERT INTO sessions (token_hash, user_id, expires_at) VALUES ($1, $2, $3)",
            token_hash,
            user_id,
            expires_at,
        )

    async def get_session_user(self, token_hash) -> User | None:
        row = await self._pool.fetchrow(
            """
            SELECT u.id, u.username, u.password_hash, u.role, u.disabled, u.created_at
            FROM sessions s JOIN users u ON u.id = s.user_id
            WHERE s.token_hash = $1 AND s.expires_at > now()
            """,
            token_hash,
        )
        return _user(row)

    async def delete_session(self, token_hash) -> None:
        await self._pool.execute("DELETE FROM sessions WHERE token_hash = $1", token_hash)

    async def revoke_user_sessions(self, user_id) -> int:
        result = await self._pool.execute("DELETE FROM sessions WHERE user_id = $1", user_id)
        return int(result.split()[-1])

    async def create_api_key(self, name, key_hash) -> ApiKey:
        row = await self._pool.fetchrow(
            "INSERT INTO api_keys (id, name, key_hash) VALUES ($1, $2, $3) RETURNING id, name, created_at",
            _new_id(),
            name,
            key_hash,
        )
        return _api_key(row)

    async def get_api_key_by_hash(self, key_hash) -> ApiKey | None:
        return _api_key(
            await self._pool.fetchrow("SELECT id, name, created_at FROM api_keys WHERE key_hash = $1", key_hash)
        )

    async def list_api_keys(self) -> list[ApiKey]:
        rows = await self._pool.fetch("SELECT id, name, created_at FROM api_keys ORDER BY created_at")
        return [_api_key(r) for r in rows]

    async def delete_api_key(self, key_id) -> bool:
        return (await self._pool.execute("DELETE FROM api_keys WHERE id = $1", key_id)).endswith("1")

    async def close(self) -> None:
        await self._pool.close()


# --- bootstrap --------------------------------------------------------------


async def ensure_admin(store: AuthStore, username: str, password: str) -> User | None:
    """Create the first admin, but only when no users exist. Returns it, else None.

    Raises ValueError for an invalid username or a password under 12 characters.
    """
    username = validate_username(normalize_username(username))
    validate_password(password)
    if await store.count_users() > 0:
        return None
    try:
        return await store.create_user(username, await hash_password_async(password), "admin")
    except DuplicateUserError:  # another replica won the race
        return None


# --- login throttling -------------------------------------------------------


class LoginThrottle:
    """Failed logins per (username, ip) in a sliding window. In-process state."""

    MAX_KEYS = 10_000

    def __init__(self, max_failures=LOGIN_MAX_FAILURES, window=LOGIN_WINDOW, clock=time.monotonic):
        self.max_failures = max_failures
        self.window = window.total_seconds()
        self._clock = clock
        self._failures: dict[tuple[str, str], deque[float]] = {}

    def _recent(self, key) -> deque[float]:
        times = self._failures.get(key)
        if times is None:
            return deque()
        cutoff = self._clock() - self.window
        while times and times[0] <= cutoff:
            times.popleft()
        if not times:
            del self._failures[key]
        return times

    def retry_after(self, username: str, ip: str) -> int | None:
        """Seconds until another attempt is allowed, or None if not blocked."""
        times = self._recent((username, ip))
        if len(times) < self.max_failures:
            return None
        return max(1, int(times[0] + self.window - self._clock()) + 1)

    def record_failure(self, username: str, ip: str) -> None:
        if len(self._failures) >= self.MAX_KEYS:
            for key in list(self._failures):
                self._recent(key)
            if len(self._failures) >= self.MAX_KEYS:  # still full: drop the oldest entries
                for key in list(self._failures)[: self.MAX_KEYS // 10]:
                    del self._failures[key]
        self._failures.setdefault((username, ip), deque()).append(self._clock())

    def reset(self, username: str, ip: str) -> None:
        self._failures.pop((username, ip), None)


def get_throttle(request: Request) -> LoginThrottle:
    state = request.app.state
    if getattr(state, "login_throttle", None) is None:
        state.login_throttle = LoginThrottle()
    return state.login_throttle


# --- request authentication -------------------------------------------------


def cookie_secure() -> bool:
    return os.getenv("COOKIE_SECURE", "true").strip().lower() != "false"


def client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def check_csrf(request: Request) -> None:
    """Cookie-authenticated unsafe requests must carry the custom header."""
    if request.method in _SAFE_METHODS:
        return
    supplied = request.headers.get(CSRF_HEADER, "")
    if not hmac.compare_digest(supplied.encode(), CSRF_VALUE.encode()):
        raise HTTPException(403, detail="missing or invalid X-Requested-With header")


def _auth_store(request: Request) -> AuthStore:
    return request.app.state.auth


async def session_user(request: Request) -> User | None:
    """The enabled user behind the session cookie, or None. Enforces CSRF when a cookie is present."""
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        return None
    check_csrf(request)
    user = await _auth_store(request).get_session_user(hash_token(token))
    if user is None or user.disabled:
        return None
    return user


def bearer_token(request: Request) -> str | None:
    header = request.headers.get("authorization", "")
    scheme, _, value = header.partition(" ")
    if scheme.lower() != "bearer" or not value.strip():
        return None
    return value.strip()


async def current_user_optional(request: Request) -> User | None:
    return await session_user(request)


async def _current_user(request: Request) -> User:
    user = await session_user(request)
    if user is None:
        raise HTTPException(401, detail="authentication required")
    return user


current_user = _current_user


def require_role(role: Role):
    """Dependency: a signed-in user with `role` or higher. API keys never pass."""
    if role not in ROLE_RANK:
        raise ValueError(f"unknown role {role!r}")
    needed = ROLE_RANK[role]

    async def dependency(request: Request) -> User:
        user = await _current_user(request)
        if ROLE_RANK[user.role] < needed:
            raise HTTPException(403, detail="insufficient role")
        return user

    return dependency


async def require_ingest(request: Request) -> User | ApiKey:
    """Dependency for POST /ingest: a valid API key (Bearer) or an analyst+ session."""
    token = bearer_token(request)
    if token is not None:
        key = await _auth_store(request).get_api_key_by_hash(hash_token(token))
        if key is None:
            raise HTTPException(401, detail="invalid API key", headers={"WWW-Authenticate": "Bearer"})
        return key
    user = await _current_user(request)
    if ROLE_RANK[user.role] < ROLE_RANK["analyst"]:
        raise HTTPException(403, detail="insufficient role")
    return user
