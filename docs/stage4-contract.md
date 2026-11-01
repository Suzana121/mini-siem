# Stage 4 contract — dashboard, events, auth

Shared by three parallel workstreams. Do not change it without telling the coordinator.
Existing code style: async, Protocol + Memory/Postgres store pair (see `app/store.py`), env config in `app/config.py`, pydantic v2, tests with pytest + anyio.

## Ownership (disjoint files)
| Stream | Owns | Must NOT touch |
|---|---|---|
| events | `app/events.py`, `app/routes/events.py`, `tests/test_events.py` | `app/main.py`, `app/config.py`, `app/pipeline.py`, `app/auth*` |
| auth | `app/auth.py`, `app/routes/auth.py`, `scripts/create_user.py`, `tests/test_auth.py` | `app/main.py`, `app/config.py`, `app/events.py` |
| web | `web/**` | everything under `app/` |

The coordinator wires routers, config, pipeline and Docker afterwards. Each stream exposes a `router = APIRouter()` and a `build_*` factory described below; routes read components from `request.app.state` (names below) and never build their own.

## Roles
`viewer` < `analyst` < `admin`. Dependency `require_role("viewer"|"analyst"|"admin")` in `app/auth.py` (accepts that role or higher) returns the `User`.

## Auth (stream: auth)
- Users: `id`, `username` (unique, lowercase), `password_hash` (argon2id via `argon2-cffi`), `role`, `disabled`, `created_at`. Sessions: opaque random token (>=32 bytes), only its SHA-256 stored; 12h expiry; sent as `session` cookie: HttpOnly, SameSite=Strict, Secure unless `COOKIE_SECURE=false`.
- CSRF: every non-GET request authenticated by cookie must carry header `X-Requested-With: mini-siem`, else 403.
- Machine access: API keys (`msk_` + random), stored hashed, role `ingest` only → may call `POST /ingest`. Header `Authorization: Bearer <key>`. `ship_logs.py` gets `--api-key` / `SIEM_API_KEY` (coordinator).
- Login throttling: 5 failures per (username, ip) per 5 min → 429. Constant-time compare, same error for unknown user / wrong password, run a dummy hash for unknown users.
- Store protocol `AuthStore` with `MemoryAuthStore` and `PostgresAuthStore` (tables `users`, `sessions`, `api_keys`), `connect(url)` classmethod like `PostgresAlertStore`. Stored in `app.state.auth`.
- Bootstrap: `ensure_admin(store, username, password)` creates the admin only if no users exist (env `ADMIN_USERNAME`, `ADMIN_PASSWORD` read by coordinator); passwords min 12 chars. `scripts/create_user.py` for CLI creation.
- Endpoints (all JSON):
  - `POST /auth/login {username,password}` → `{user}` + cookie. `POST /auth/logout` → 204. `GET /auth/me` → `{id,username,role}` (401 if none).
  - `GET /users` (admin) · `POST /users {username,password,role}` (admin) · `PATCH /users/{id} {role?,disabled?,password?}` (admin; cannot demote/disable the last enabled admin) .
  - `GET /api-keys` (admin; never returns the secret) · `POST /api-keys {name}` → `{id,name,key}` (secret shown once) · `DELETE /api-keys/{id}` (admin).
  - Disabling a user or changing their password revokes their sessions.
- Dependencies exported: `require_role(role)`, `require_ingest` (API key OR analyst+ session), `current_user_optional`.

## Events (stream: events)
- `EventStore` protocol + `MemoryEventStore` (bounded deque) + `PostgresEventStore` (table `events`: `id BIGSERIAL`, `ts`, `host`, `source_ip INET`, `user_name`, `action`, `outcome`, `body JSONB` = NormalizedEvent). Indexes `(source_ip, ts)`, `(host, ts)`, `(ts)`. Methods: `add(events: list[NormalizedEvent])`, `query(*, source_ip, user, host, since, until, limit, offset) -> list[NormalizedEvent]`, `prune(older_than)`, `close()`. `connect(url, retention)`; stored in `app.state.events`.
- Endpoints (role `viewer`+):
  - `GET /events?source_ip=&user=&host=&since=&until=&around=<ts>&window=15m&limit<=1000&offset=`. `around`+`window` is shorthand for since/until.
  - `GET /alerts/{id}/events` → events matching the alert's `group` fields / source.ip / host between `first_seen - 5m` and `last_seen + 5m` (uses `app.state.store.get`). 404 if alert missing.
  - `GET /stats/summary` → `{by_status:{open,acknowledged,closed}, by_severity:{low,medium,high,critical}, last_24h:int, top_source_ips:[{ip,alerts,max_risk}], top_users:[{user,alerts}]}` (top 10, from `app.state.store`; needs a new `AlertStore.all_since(since)`-style helper — implement it as a function in `app/events.py` that only uses `store.list(limit=1000)` to avoid editing `app/store.py`).
  - `GET /stats/attack?since=` → `{tactics:[{tactic, techniques:[{id,name,alerts,max_severity}]}]}` ordered by ATT&CK tactic order (Reconnaissance … Impact).
- Retention: `prune` called hourly by a helper `async def retention_loop(store, retention)` that the coordinator runs in app lifespan / worker.

## Alerts API additions (coordinator)
`GET /alerts` gains `q` (substring over source ip, user, host, rule), `since`, `offset`. `PATCH /alerts/{id}` requires analyst+. All alert/rule/health-detail routes require viewer+; `/health` stays public (minimal body); `POST /ingest` requires `require_ingest`.

## Web (stream: web)
React 18 + TypeScript + Vite + React Router + TanStack Query, plain CSS (no UI kit). Lives in `web/`; `npm run build` → `web/dist` (served by FastAPI at `/`, SPA fallback; API stays at its current paths). Dev: Vite proxy of API paths to `http://localhost:8000`. Pages: Login; Alerts (KPI bar from `/stats/summary`, filter bar, table sorted by last_seen, 5s refresh); Alert detail drawer/page (MITRE chips, risk factors, enrichment, evidence, related events tab, Acknowledge/Close visible to analyst+); ATT&CK heatmap (tactic columns, technique cells shaded by alert count, click → Alerts filtered by technique via `q`... use `rule_id` list from `/rules` mitre mapping); Admin (users + API keys, admin only). Send `X-Requested-With: mini-siem` and `credentials: 'same-origin'` on all requests; 401 → redirect to login. Render log text only through React text nodes (never `dangerouslySetInnerHTML`). Light + dark via `prefers-color-scheme`. Tests: vitest + testing-library for api client, role gating, heatmap shading. Types mirror `app/store.py::StoredAlert` and `app/schema.py`.
