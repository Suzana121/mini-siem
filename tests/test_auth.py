"""Auth stores, login flow, role gating, CSRF, throttling and API keys.

The Postgres variant runs when TEST_DATABASE_URL is set (see tests/test_store.py);
it truncates users, sessions and api_keys, so never point it at real data.
"""

import os
from datetime import timedelta

import httpx
import pytest
from fastapi import Depends, FastAPI

from app import auth
from app.auth import MemoryAuthStore, PostgresAuthStore
from app.routes.auth import router

pytestmark = pytest.mark.anyio
PASSWORD = "correct horse battery"
CSRF = {"X-Requested-With": "mini-siem"}


@pytest.fixture(params=["memory", "postgres"])
async def store(request):
    if request.param == "memory":
        yield MemoryAuthStore()
        return
    url = os.getenv("TEST_DATABASE_URL")
    if not url:
        pytest.skip("TEST_DATABASE_URL not set")
    store = await PostgresAuthStore.connect(url)
    await store._pool.execute("TRUNCATE users, sessions, api_keys CASCADE")
    yield store
    await store.close()


@pytest.fixture(autouse=True)
def insecure_cookies(monkeypatch):
    monkeypatch.setenv("COOKIE_SECURE", "false")  # test client speaks plain http


def build_app(store) -> FastAPI:
    app = FastAPI()
    app.state.auth = store
    app.include_router(router)

    @app.get("/viewer")
    async def viewer(user=Depends(auth.require_role("viewer"))):
        return {"u": user.username}

    @app.get("/analyst")
    async def analyst(user=Depends(auth.require_role("analyst"))):
        return {"u": user.username}

    @app.post("/analyst-write")
    async def analyst_write(user=Depends(auth.require_role("analyst"))):
        return {"u": user.username}

    @app.post("/ingest")
    async def ingest(principal=Depends(auth.require_ingest)):
        return {"ok": True}

    @app.get("/optional")
    async def optional(user=Depends(auth.current_user_optional)):
        return {"u": user.username if user else None}

    return app


async def add_user(store, username, role="viewer", password=PASSWORD):
    return await store.create_user(username, await auth.hash_password_async(password), role)


@pytest.fixture
async def app(store):
    await add_user(store, "admin", "admin")
    await add_user(store, "analyst", "analyst")
    await add_user(store, "viewer", "viewer")
    return build_app(store)


def new_client(app) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver")


@pytest.fixture
async def client(app):
    async with new_client(app) as c:
        yield c


async def login(client, username, password=PASSWORD):
    return await client.post("/auth/login", json={"username": username, "password": password})


class login_as:
    """`async with login_as(app, "admin") as client:` yields a logged-in client."""

    def __init__(self, app, username):
        self.app, self.username = app, username

    async def __aenter__(self):
        self.client = new_client(self.app)
        await self.client.__aenter__()
        assert (await login(self.client, self.username)).status_code == 200
        return self.client

    async def __aexit__(self, *exc):
        await self.client.__aexit__(*exc)


# --- hashing / helpers --------------------------------------------------------


def test_password_hash_is_argon2id_and_verifies():
    h = auth.hash_password(PASSWORD)
    assert h.startswith("$argon2id$")
    assert auth.verify_password(h, PASSWORD)
    assert not auth.verify_password(h, PASSWORD + "x")
    assert not auth.verify_password("not-a-hash", PASSWORD)


# --- store --------------------------------------------------------------------


async def test_ensure_admin_only_when_empty(store):
    admin = await auth.ensure_admin(store, "Root", PASSWORD)
    assert admin and admin.username == "root" and admin.role == "admin"
    assert await auth.ensure_admin(store, "other", PASSWORD) is None
    assert await store.count_users() == 1


async def test_ensure_admin_rejects_short_password(store):
    with pytest.raises(ValueError):
        await auth.ensure_admin(store, "root", "short")
    assert await store.count_users() == 0


async def test_duplicate_username(store):
    await add_user(store, "alice")
    with pytest.raises(auth.DuplicateUserError):
        await add_user(store, "alice")


async def test_sessions_hashed_expire_and_revoke(store, monkeypatch):
    user = await add_user(store, "alice")
    expires = auth._now() + timedelta(hours=1)
    await store.create_session(user.id, "h1", expires)
    await store.create_session(user.id, "h2", expires)
    assert (await store.get_session_user("h1")).id == user.id
    assert await store.revoke_user_sessions(user.id) == 2
    assert await store.get_session_user("h1") is None
    await store.create_session(user.id, "h3", auth._now() - timedelta(seconds=1))
    assert await store.get_session_user("h3") is None


async def test_last_admin_protection_in_store(store):
    a = await add_user(store, "a", "admin")
    b = await add_user(store, "b", "admin")
    await store.update_user(a.id, role="viewer")
    with pytest.raises(auth.LastAdminError):
        await store.update_user(b.id, disabled=True)
    with pytest.raises(auth.LastAdminError):
        await store.update_user(b.id, role="analyst")
    assert (await store.update_user(b.id, password_hash="x")).role == "admin"


# --- login / logout / me ------------------------------------------------------


async def test_login_sets_hardened_cookie_and_me_works(client, store):
    r = await login(client, "Analyst ")
    assert r.status_code == 200
    assert r.json()["user"] == {"id": r.json()["user"]["id"], "username": "analyst", "role": "analyst"}
    assert "password" not in r.text
    cookie = r.headers["set-cookie"].lower()
    assert "session=" in cookie and "httponly" in cookie and "samesite=strict" in cookie
    assert "secure" not in cookie  # COOKIE_SECURE=false in tests
    token = client.cookies["session"]
    assert len(token) >= 43
    # Only the hash is stored.
    assert await store.get_session_user(token) is None
    assert (await store.get_session_user(auth.hash_token(token))).username == "analyst"
    me = await client.get("/auth/me")
    assert me.status_code == 200 and me.json()["role"] == "analyst"


async def test_cookie_is_secure_by_default(app, monkeypatch):
    monkeypatch.delenv("COOKIE_SECURE")
    async with new_client(app) as c:
        r = await login(c, "viewer")
    assert "secure" in r.headers["set-cookie"].lower()


async def test_me_requires_login(client):
    assert (await client.get("/auth/me")).status_code == 401


async def test_login_errors_are_uniform(client, store):
    await store.update_user((await store.get_user_by_username("viewer")).id, disabled=True)
    wrong = await login(client, "analyst", "wrong password!!")
    unknown = await login(client, "nobody")
    disabled = await login(client, "viewer")
    assert {wrong.status_code, unknown.status_code, disabled.status_code} == {401}
    assert wrong.json() == unknown.json() == disabled.json()
    assert "session" not in client.cookies


async def test_unknown_user_still_runs_a_hash(client, monkeypatch):
    calls = []
    real = auth.verify_password

    def spy(stored_hash, password):
        calls.append(stored_hash)
        return real(stored_hash, password)

    monkeypatch.setattr(auth, "verify_password", spy)
    await login(client, "nobody")
    assert calls == [auth.dummy_hash()]


async def test_logout_revokes_session(client):
    await login(client, "viewer")
    token = client.cookies["session"]
    assert (await client.post("/auth/logout")).status_code == 403  # CSRF header required
    r = await client.post("/auth/logout", headers=CSRF)
    assert r.status_code == 204
    assert "session=" in r.headers["set-cookie"]  # cleared
    client.cookies.set("session", token)  # replay the old cookie
    assert (await client.get("/auth/me")).status_code == 401


async def test_session_expiry(client, monkeypatch):
    await login(client, "viewer")
    assert (await client.get("/viewer")).status_code == 200
    real = auth._now
    monkeypatch.setattr(auth, "_now", lambda: real() + auth.SESSION_TTL + timedelta(seconds=1))
    assert (await client.get("/viewer")).status_code == 401


# --- throttling ---------------------------------------------------------------


async def test_login_throttling(client):
    for _ in range(5):
        assert (await login(client, "analyst", "wrong password!!")).status_code == 401
    blocked = await login(client, "analyst")  # even the right password is refused now
    assert blocked.status_code == 429
    assert int(blocked.headers["retry-after"]) > 0
    assert (await login(client, "viewer")).status_code == 200  # other usernames unaffected


def test_throttle_window_slides_and_resets():
    now = [0.0]
    t = auth.LoginThrottle(clock=lambda: now[0])
    for _ in range(5):
        t.record_failure("u", "1.1.1.1")
    assert t.retry_after("u", "1.1.1.1")
    assert t.retry_after("u", "2.2.2.2") is None  # per (username, ip)
    now[0] = 301
    assert t.retry_after("u", "1.1.1.1") is None
    for _ in range(5):
        t.record_failure("u", "1.1.1.1")
    t.reset("u", "1.1.1.1")
    assert t.retry_after("u", "1.1.1.1") is None


async def test_successful_login_clears_failures(client):
    for _ in range(4):
        await login(client, "analyst", "wrong password!!")
    assert (await login(client, "analyst")).status_code == 200
    for _ in range(4):
        await login(client, "analyst", "wrong password!!")
    assert (await login(client, "analyst")).status_code == 200


# --- role gating --------------------------------------------------------------


@pytest.mark.parametrize(
    "user,viewer,analyst,admin",
    [("viewer", 200, 403, 403), ("analyst", 200, 200, 403), ("admin", 200, 200, 200)],
)
async def test_role_hierarchy(app, user, viewer, analyst, admin):
    async with login_as(app, user) as c:
        assert (await c.get("/viewer")).status_code == viewer
        assert (await c.get("/analyst")).status_code == analyst
        assert (await c.get("/users")).status_code == admin


async def test_anonymous_gets_401(client):
    for path in ("/viewer", "/analyst", "/users", "/api-keys"):
        assert (await client.get(path)).status_code == 401
    assert (await client.get("/optional")).json() == {"u": None}


async def test_optional_user(app):
    async with login_as(app, "viewer") as c:
        assert (await c.get("/optional")).json() == {"u": "viewer"}


# --- CSRF ---------------------------------------------------------------------


async def test_csrf_header_required_for_unsafe_cookie_requests(app):
    async with login_as(app, "admin") as c:
        assert (await c.post("/analyst-write")).status_code == 403
        assert (await c.post("/analyst-write", headers={"X-Requested-With": "other"})).status_code == 403
        assert (await c.post("/analyst-write", headers=CSRF)).status_code == 200
        assert (await c.get("/analyst")).status_code == 200  # GET needs no header
        r = await c.post("/users", json={"username": "newbie", "password": PASSWORD, "role": "viewer"})
        assert r.status_code == 403


# --- user management ----------------------------------------------------------


async def test_admin_manages_users(app, store):
    async with login_as(app, "admin") as c:
        r = await c.post(
            "/users", json={"username": "Newbie", "password": PASSWORD, "role": "analyst"}, headers=CSRF
        )
        assert r.status_code == 201
        assert r.json()["username"] == "newbie" and "password" not in r.text
        dup = await c.post("/users", json={"username": "newbie", "password": PASSWORD, "role": "viewer"}, headers=CSRF)
        assert dup.status_code == 409
        short = await c.post("/users", json={"username": "x-user", "password": "short", "role": "viewer"}, headers=CSRF)
        assert short.status_code == 422
        bad_role = await c.post("/users", json={"username": "x-user", "password": PASSWORD, "role": "root"}, headers=CSRF)
        assert bad_role.status_code == 422
        listing = (await c.get("/users")).json()
        assert {u["username"] for u in listing} == {"admin", "analyst", "viewer", "newbie"}
        assert all("password" not in u and "password_hash" not in u for u in listing)


async def test_non_admin_cannot_manage_users(app):
    async with login_as(app, "analyst") as c:
        r = await c.post("/users", json={"username": "evil", "password": PASSWORD, "role": "admin"}, headers=CSRF)
        assert r.status_code == 403


async def test_disable_and_password_change_revoke_sessions(app, store):
    viewer = await store.get_user_by_username("viewer")
    async with login_as(app, "viewer") as v, login_as(app, "admin") as admin:
        assert (await v.get("/auth/me")).status_code == 200
        r = await admin.patch(f"/users/{viewer.id}", json={"password": "a brand new password"}, headers=CSRF)
        assert r.status_code == 200
        assert (await v.get("/auth/me")).status_code == 401
        assert (await login(v, "viewer")).status_code == 401  # old password
        assert (await login(v, "viewer", "a brand new password")).status_code == 200
        assert (await admin.patch(f"/users/{viewer.id}", json={"disabled": True}, headers=CSRF)).status_code == 200
        assert (await v.get("/auth/me")).status_code == 401
        assert (await login(v, "viewer", "a brand new password")).status_code == 401
        assert (await admin.patch("/users/nope", json={"role": "viewer"}, headers=CSRF)).status_code == 404


async def test_role_change_takes_effect_immediately(app, store):
    viewer = await store.get_user_by_username("viewer")
    async with login_as(app, "viewer") as v, login_as(app, "admin") as admin:
        assert (await v.get("/analyst")).status_code == 403
        await admin.patch(f"/users/{viewer.id}", json={"role": "analyst"}, headers=CSRF)
        assert (await v.get("/analyst")).status_code == 200


async def test_last_admin_cannot_be_demoted_or_disabled(app, store):
    admin_user = await store.get_user_by_username("admin")
    async with login_as(app, "admin") as c:
        url = f"/users/{admin_user.id}"
        assert (await c.patch(url, json={"role": "viewer"}, headers=CSRF)).status_code == 409
        assert (await c.patch(url, json={"disabled": True}, headers=CSRF)).status_code == 409
        assert (await c.patch(url, json={"password": PASSWORD + "!"}, headers=CSRF)).status_code == 200
        assert (await c.get("/auth/me")).status_code == 401  # own password change revoked this session
        assert (await login(c, "admin", PASSWORD + "!")).status_code == 200
        # With a second admin, demotion is fine, and then the other one is protected.
        second = await add_user(store, "admin2", "admin")
        assert (await c.patch(url, json={"role": "viewer"}, headers=CSRF)).status_code == 200
    async with login_as(app, "admin2") as c2:
        assert (await c2.patch(f"/users/{second.id}", json={"disabled": True}, headers=CSRF)).status_code == 409


# --- API keys -----------------------------------------------------------------


async def test_api_key_lifecycle_and_ingest_access(app, store):
    async with login_as(app, "admin") as admin, new_client(app) as machine:
        r = await admin.post("/api-keys", json={"name": "web01"}, headers=CSRF)
        assert r.status_code == 201
        body = r.json()
        secret = body["key"]
        assert secret.startswith("msk_") and len(secret) >= 40

        listing = (await admin.get("/api-keys")).json()
        assert [k["name"] for k in listing] == ["web01"]
        assert secret not in (await admin.get("/api-keys")).text
        assert await store.get_api_key_by_hash(secret) is None  # stored hashed
        assert (await store.get_api_key_by_hash(auth.hash_token(secret))).id == body["id"]

        bearer = {"Authorization": f"Bearer {secret}"}
        assert (await machine.post("/ingest", headers=bearer)).status_code == 200
        # An API key is for ingest only.
        for path in ("/viewer", "/users", "/auth/me", "/api-keys"):
            assert (await machine.get(path, headers=bearer)).status_code == 401
        bad = await machine.post("/ingest", headers={"Authorization": "Bearer msk_wrong"})
        assert bad.status_code == 401
        assert (await machine.post("/ingest")).status_code == 401

        assert (await admin.delete(f"/api-keys/{body['id']}", headers=CSRF)).status_code == 204
        assert (await machine.post("/ingest", headers=bearer)).status_code == 401
        assert (await admin.delete(f"/api-keys/{body['id']}", headers=CSRF)).status_code == 404


async def test_ingest_session_needs_analyst(app):
    async with login_as(app, "viewer") as v:
        assert (await v.post("/ingest", headers=CSRF)).status_code == 403
    async with login_as(app, "analyst") as a:
        assert (await a.post("/ingest")).status_code == 403  # no CSRF header
        assert (await a.post("/ingest", headers=CSRF)).status_code == 200


async def test_api_key_endpoints_are_admin_only(app):
    async with login_as(app, "analyst") as c:
        assert (await c.get("/api-keys")).status_code == 403
        assert (await c.post("/api-keys", json={"name": "x"}, headers=CSRF)).status_code == 403
        assert (await c.delete("/api-keys/abc", headers=CSRF)).status_code == 403
