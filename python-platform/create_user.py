"""Create a local pilot admin. Example: python create_user.py email@example.com"""
import getpass, sys
from app.main import db, uid, now, hash_pw
if len(sys.argv)!=2: raise SystemExit("Usage: python create_user.py EMAIL")
email=sys.argv[1].strip().lower(); password=getpass.getpass("Password (12+ chars): ")
if len(password)<12: raise SystemExit("Use at least 12 characters")
with db() as c:
    c.execute("INSERT INTO users VALUES(?,?,?,?,?,?)",(uid("usr"),email,hash_pw(password),"admin",__import__('secrets').token_urlsafe(32),now()))
print("Admin account created.")
