"""Create an API key via the Mini-SIEM HTTP API (admin login, then POST /api-keys).

Usage:
    python -m scripts.create_api_key lab-shipper --url http://api:8000 \
        --admin-username admin --admin-password "$ADMIN_PASSWORD" \
        --out /shared/api-key

Logs in as an admin user, creates a named API key, and prints the secret
(or writes it to --out, useful for a shared volume read by another
container). Retries the login/health check for a while so it can run as a
one-shot container that starts before the API is fully up.
"""

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request


def _request(url: str, method: str = "GET", body: dict | None = None, headers: dict | None = None) -> tuple[int, dict, dict]:
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers={"Content-Type": "application/json", **(headers or {})})
    try:
        with urllib.request.urlopen(req) as resp:
            cookies = resp.headers.get_all("Set-Cookie") or []
            payload = json.loads(resp.read() or b"{}")
            return resp.status, payload, {"Set-Cookie": "; ".join(c.split(";")[0] for c in cookies)}
    except urllib.error.HTTPError as e:
        payload = json.loads(e.read() or b"{}") if e.fp else {}
        return e.code, payload, {}


def wait_for_health(url: str, timeout: float) -> None:
    deadline = time.monotonic() + timeout
    last_err = None
    while time.monotonic() < deadline:
        try:
            urllib.request.urlopen(f"{url}/health", timeout=3)
            return
        except Exception as e:  # noqa: BLE001 - keep retrying until timeout
            last_err = e
            time.sleep(1)
    raise RuntimeError(f"API never became healthy at {url}: {last_err}")


def create_api_key(url: str, admin_username: str, admin_password: str, name: str, timeout: float = 60.0) -> str:
    wait_for_health(url, timeout)
    status, body, headers = _request(
        f"{url}/auth/login", "POST", {"username": admin_username, "password": admin_password}
    )
    if status != 200:
        raise RuntimeError(f"admin login failed ({status}): {body}")
    cookie = headers.get("Set-Cookie", "")
    if not cookie:
        raise RuntimeError("login succeeded but no session cookie was returned")

    status, body, _ = _request(
        f"{url}/api-keys",
        "POST",
        {"name": name},
        headers={"Cookie": cookie, "X-Requested-With": "mini-siem"},
    )
    if status != 201:
        raise RuntimeError(f"creating API key failed ({status}): {body}")
    return body["key"]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("name")
    parser.add_argument("--url", default=os.getenv("SIEM_URL", "http://localhost:8000"))
    parser.add_argument("--admin-username", default=os.getenv("ADMIN_USERNAME", "admin"))
    parser.add_argument("--admin-password", default=os.getenv("ADMIN_PASSWORD"))
    parser.add_argument("--out", help="write the secret to this file instead of stdout")
    parser.add_argument("--timeout", type=float, default=60.0, help="seconds to wait for the API to come up")
    args = parser.parse_args()

    if not args.admin_password:
        print("ADMIN_PASSWORD (or --admin-password) is required", file=sys.stderr)
        return 2

    try:
        key = create_api_key(args.url, args.admin_username, args.admin_password, args.name, args.timeout)
    except RuntimeError as e:
        print(e, file=sys.stderr)
        return 1

    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(key)
        print(f"wrote API key '{args.name}' to {args.out}")
    else:
        print(key)
    return 0


if __name__ == "__main__":
    sys.exit(main())
