"""Interactive local setup and operator commands. Never accept passwords on argv."""
import argparse
import getpass
import json
import os
import secrets
from pathlib import Path
from sqlalchemy import select
from .config import Settings, ROOT, load_settings
from .database import database
from .models import User
from .services import password_hasher, audit, verify_audit

def main():
    parser=argparse.ArgumentParser(description="Sentinel operator CLI")
    parser.add_argument("command",choices=["init-config","create-user","verify-audit","has-users"])
    parser.add_argument("--username")
    parser.add_argument("--role",choices=["administrator","analyst"],default="administrator")
    args=parser.parse_args()
    if args.command=="init-config":
        target=ROOT/".env"
        if target.exists(): raise SystemExit("Configuration already exists; it was not overwritten.")
        database_url=getpass.getpass("PostgreSQL SQLAlchemy URL (hidden): ").strip()
        if not database_url.startswith("postgresql+psycopg://"): raise SystemExit("A PostgreSQL psycopg URL is required.")
        secret=secrets.token_urlsafe(48)
        # JSON-quoted dotenv values safely preserve punctuation and spaces.
        target.write_text(f'SENTINEL_ENVIRONMENT=development\nSENTINEL_DATABASE_URL={json.dumps(database_url)}\nSENTINEL_SESSION_SECRET={json.dumps(secret)}\n',encoding="utf8")
        if os.name!="nt": target.chmod(0o600)
        print("Local configuration created. Keep it outside source control.")
        return
    settings=load_settings(); engine,sessions=database(settings)
    try:
        with sessions() as db:
            if args.command=="has-users":
                raise SystemExit(0 if db.scalar(select(User.id).where(User.role=="administrator",User.active.is_(True)).limit(1)) else 3)
            if args.command=="verify-audit":
                valid=verify_audit(db)
                print("Audit chain valid" if valid else "Audit verification FAILED")
                raise SystemExit(0 if valid else 1)
            username=(args.username or input("Username: ")).lower().strip()
            if not 3<=len(username)<=100 or any(c not in "abcdefghijklmnopqrstuvwxyz0123456789_.@-" for c in username): raise SystemExit("Invalid username")
            if db.scalar(select(User.id).where(User.username==username)): raise SystemExit("Username already exists")
            password=getpass.getpass("Password (at least 12 characters): ")
            if len(password)<12 or len(password)>256: raise SystemExit("Password must contain 12 to 256 characters")
            if password!=getpass.getpass("Confirm password: "): raise SystemExit("Passwords did not match")
            user=User(username=username,role=args.role,password_hash=password_hasher.hash(password))
            db.add(user);db.flush()
            audit(db,"operator","user.created",user.id)
            db.commit()
            print(f"Created {args.role} account: {username}")
    finally: engine.dispose()

if __name__=="__main__": main()
