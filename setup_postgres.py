"""
setup_postgres.py - ThreatPulse AI PostgreSQL Setup
Run: python setup_postgres.py
"""

import os, sys

# Load .env FIRST before anything else
try:
    from dotenv import load_dotenv
    load_dotenv(os.path.join(os.path.dirname(__file__), '.env'))
    print("✓ .env loaded")
except:
    pass

print("=" * 55)
print("  ThreatPulse AI — PostgreSQL Setup")
print("=" * 55)

# Check psycopg2
print("\n[1/4] Checking psycopg2...")
try:
    import psycopg2
    print("  ✓ psycopg2 installed")
except ImportError:
    os.system("pip install psycopg2-binary")
    import psycopg2

# Read config
host     = os.environ.get("PG_HOST",     "localhost")
port     = int(os.environ.get("PG_PORT", "5432"))
user     = os.environ.get("PG_USER",     "postgres")
password = os.environ.get("PG_PASSWORD", "")
target   = os.environ.get("PG_DB",       "threatpulse")

print(f"\n[2/4] Connecting to {host}:{port} as '{user}'...")
print(f"  Password loaded: {'YES (' + '*'*len(password) + ')' if password else 'NO — check .env'}")

if not password:
    print("\n  ✗ PG_PASSWORD is empty in .env")
    print("  Open C:\\cyber\\files\\.env and set:")
    print("  PG_PASSWORD=your_password_here")
    sys.exit(1)

# Try connect
try:
    conn = psycopg2.connect(
        host=host, port=port,
        user=user, password=password,
        dbname="postgres"
    )
    conn.autocommit = True
    print(f"  ✓ Connected!")
except Exception as e:
    print(f"  ✗ Failed: {e}")
    print("\n  Try these fixes:")
    print("  1. Check PG_PASSWORD in .env matches your PostgreSQL password")
    print("  2. Make sure PostgreSQL service is running:")
    print("     net start postgresql-x64-17")
    print("  3. Try running pgAdmin and login with same password")
    sys.exit(1)

# Create database
print(f"\n[3/4] Creating database '{target}'...")
cur = conn.cursor()
cur.execute("SELECT 1 FROM pg_database WHERE datname = %s", (target,))
if cur.fetchone():
    print(f"  ✓ Database '{target}' already exists")
else:
    cur.execute(f'CREATE DATABASE "{target}"')
    print(f"  ✓ Database '{target}' created")
conn.close()

# Create tables
print("\n[4/4] Creating tables...")
try:
    # Patch DB_CONFIG manually since we're not importing api.py
    os.environ["PG_DB"] = target
    sys.path.insert(0, os.path.dirname(__file__))
    from database import init_db
    init_db()
    print("  ✓ Tables created: packets, threats, stats")
except Exception as e:
    print(f"  ✗ Table creation failed: {e}")
    sys.exit(1)

print("\n" + "=" * 55)
print("  ✓ PostgreSQL setup complete!")
print("=" * 55)
print(f"\n  Database : {target}")
print(f"  Host     : {host}:{port}")
print(f"  User     : {user}")
print("\n  Now run: python api.py")
