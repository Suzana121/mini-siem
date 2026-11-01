"""Create a user in the auth database.

Usage (from the repo root; DATABASE_URL must point at PostgreSQL):
    python -m scripts.create_user alice --role analyst
The password is read from SIEM_PASSWORD or prompted for -- never passed as an argument.
"""

import argparse
import asyncio
import getpass
import os
import sys

from app import auth


async def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("username")
    parser.add_argument("--role", choices=sorted(auth.ROLE_RANK), default="viewer")
    parser.add_argument("--database-url", default=os.getenv("DATABASE_URL"))
    args = parser.parse_args()

    if not args.database_url:
        print("DATABASE_URL (or --database-url) is required", file=sys.stderr)
        return 2
    password = os.getenv("SIEM_PASSWORD") or getpass.getpass("Password: ")
    try:
        username = auth.validate_username(auth.normalize_username(args.username))
        auth.validate_password(password)
    except ValueError as e:
        print(e, file=sys.stderr)
        return 2

    store = await auth.PostgresAuthStore.connect(args.database_url)
    try:
        await store.create_user(username, await auth.hash_password_async(password), args.role)
    except auth.DuplicateUserError:
        print(f"user '{username}' already exists", file=sys.stderr)
        return 1
    finally:
        await store.close()
    print(f"created {args.role} '{username}'")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
