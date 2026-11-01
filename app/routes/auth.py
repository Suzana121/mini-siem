"""Login, user management and API key endpoints. The store lives in request.app.state.auth."""

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, ConfigDict, Field, field_validator

from app import auth
from app.auth import ApiKey, Role, User

router = APIRouter()
require_admin = auth.require_role("admin")


def _public(user: User) -> dict:
    return {"id": user.id, "username": user.username, "role": user.role}


def _admin_view(user: User) -> dict:
    return {**_public(user), "disabled": user.disabled, "created_at": user.created_at}


class LoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    username: str = Field(max_length=128)
    password: str = Field(max_length=1024)


class UserCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    username: str
    password: str
    role: Role

    @field_validator("username")
    @classmethod
    def _username(cls, v: str) -> str:
        return auth.validate_username(auth.normalize_username(v))

    @field_validator("password")
    @classmethod
    def _password(cls, v: str) -> str:
        return auth.validate_password(v)


class UserUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    role: Role | None = None
    disabled: bool | None = None
    password: str | None = None

    @field_validator("password")
    @classmethod
    def _password(cls, v: str | None) -> str | None:
        return None if v is None else auth.validate_password(v)


class ApiKeyCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=100)


@router.post("/auth/login")
async def login(body: LoginRequest, request: Request, response: Response) -> dict:
    store = request.app.state.auth
    throttle = auth.get_throttle(request)
    username, ip = auth.normalize_username(body.username), auth.client_ip(request)

    wait = throttle.retry_after(username, ip)
    if wait is not None:
        raise HTTPException(429, detail="too many failed logins, try again later", headers={"Retry-After": str(wait)})

    user = await store.get_user_by_username(username)
    # Unknown users still verify against a dummy hash so timing does not reveal them.
    password_ok = await auth.verify_password_async(user.password_hash if user else auth.dummy_hash(), body.password)
    if user is None or not password_ok or user.disabled:
        throttle.record_failure(username, ip)
        raise HTTPException(401, detail="invalid username or password")

    throttle.reset(username, ip)
    token = auth.new_session_token()
    await store.create_session(user.id, auth.hash_token(token), auth._now() + auth.SESSION_TTL)
    response.set_cookie(
        auth.SESSION_COOKIE,
        token,
        max_age=int(auth.SESSION_TTL.total_seconds()),
        httponly=True,
        samesite="strict",
        secure=auth.cookie_secure(),
        path="/",
    )
    response.headers["Cache-Control"] = "no-store"
    return {"user": _public(user)}


@router.post("/auth/logout", status_code=204)
async def logout(request: Request) -> Response:
    token = request.cookies.get(auth.SESSION_COOKIE)
    if token:
        auth.check_csrf(request)
        await request.app.state.auth.delete_session(auth.hash_token(token))
    response = Response(status_code=204)
    response.delete_cookie(
        auth.SESSION_COOKIE, path="/", httponly=True, samesite="strict", secure=auth.cookie_secure()
    )
    return response


@router.get("/auth/me")
async def me(user: User = Depends(auth.current_user)) -> dict:
    return _public(user)


@router.get("/users")
async def list_users(request: Request, _: User = Depends(require_admin)) -> list[dict]:
    return [_admin_view(u) for u in await request.app.state.auth.list_users()]


@router.post("/users", status_code=201)
async def create_user(body: UserCreate, request: Request, _: User = Depends(require_admin)) -> dict:
    store = request.app.state.auth
    try:
        user = await store.create_user(body.username, await auth.hash_password_async(body.password), body.role)
    except auth.DuplicateUserError:
        raise HTTPException(409, detail="username already exists")
    return _admin_view(user)


@router.patch("/users/{user_id}")
async def update_user(user_id: str, body: UserUpdate, request: Request, _: User = Depends(require_admin)) -> dict:
    store = request.app.state.auth
    password_hash = await auth.hash_password_async(body.password) if body.password is not None else None
    try:
        user = await store.update_user(
            user_id, role=body.role, disabled=body.disabled, password_hash=password_hash
        )
    except auth.LastAdminError:
        raise HTTPException(409, detail="cannot demote or disable the last enabled admin")
    if user is None:
        raise HTTPException(404, detail="user not found")
    return _admin_view(user)


@router.get("/api-keys")
async def list_api_keys(request: Request, _: User = Depends(require_admin)) -> list[ApiKey]:
    return await request.app.state.auth.list_api_keys()


@router.post("/api-keys", status_code=201)
async def create_api_key(body: ApiKeyCreate, request: Request, _: User = Depends(require_admin)) -> dict:
    secret = auth.new_api_key()
    key = await request.app.state.auth.create_api_key(body.name.strip() or "unnamed", auth.hash_token(secret))
    return {"id": key.id, "name": key.name, "key": secret}  # the only time the secret is returned


@router.delete("/api-keys/{key_id}", status_code=204)
async def delete_api_key(key_id: str, request: Request, _: User = Depends(require_admin)) -> Response:
    if not await request.app.state.auth.delete_api_key(key_id):
        raise HTTPException(404, detail="API key not found")
    return Response(status_code=204)
