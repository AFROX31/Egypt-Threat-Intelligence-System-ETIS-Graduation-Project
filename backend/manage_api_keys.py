"""
manage_api_keys.py

Create, list and revoke per-client API keys (see app/core/api_keys.py).
Run from the backend folder:

    py -3.13 manage_api_keys.py create gmail-extension
    py -3.13 manage_api_keys.py list
    py -3.13 manage_api_keys.py revoke gmail-extension

`create` prints the new key ONCE. Copy it straight into the program that
will use it (for the extension: its Options page). It cannot be shown again;
if it is lost, revoke the client and create a new one.
"""

import argparse
import sys

from app.core.api_keys import create_api_client, list_api_clients, revoke_api_client
from app.core.database import Base, SessionLocal, engine
import app.models  # noqa: F401 -- registers the api_clients table


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Manage ETIS per-client API keys.")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("create", help="create a client and print its key once").add_argument("name")
    commands.add_parser("list", help="list clients (never shows keys)")
    commands.add_parser("revoke", help="revoke a client's key").add_argument("name")
    args = parser.parse_args(argv)

    Base.metadata.create_all(bind=engine, tables=[Base.metadata.tables["api_clients"]])
    with SessionLocal() as db:
        try:
            if args.command == "create":
                client, key = create_api_client(db, args.name)
                print(f"Created client {client.name!r}. Its key (shown only this once):\n\n    {key}\n")
                print("Send it in the X-API-Key header. Revoke it with: manage_api_keys.py revoke " + client.name)
            elif args.command == "list":
                clients = list_api_clients(db)
                if not clients:
                    print("No API clients yet.")
                for client in clients:
                    status = "active" if client.revoked_at is None else f"revoked {client.revoked_at:%Y-%m-%d %H:%M}"
                    last_used = f"{client.last_used_at:%Y-%m-%d %H:%M}" if client.last_used_at else "never"
                    print(f"{client.name:<24} {client.key_prefix}...  {status:<24} last used {last_used}")
            else:
                client = revoke_api_client(db, args.name)
                print(f"Revoked {client.name!r}. Requests with its key now get 401.")
        except ValueError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
