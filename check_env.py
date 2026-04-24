"""
check_env.py — Run this to see exactly what password is being read from .env
"""
import os

# Try loading .env manually
env_path = os.path.join(os.path.dirname(__file__), '.env')
print(f"Looking for .env at: {env_path}")
print(f".env exists: {os.path.exists(env_path)}")

# Read raw
if os.path.exists(env_path):
    lines = open(env_path).readlines()
    print("\nPostgreSQL lines in .env:")
    for line in lines:
        if 'PG_' in line:
            key = line.split('=')[0].strip()
            val = line.split('=',1)[1].strip() if '=' in line else ''
            if 'PASSWORD' in key:
                print(f"  {key} = {'*' * len(val)} ({len(val)} chars)")
            else:
                print(f"  {key} = {val}")

# Try dotenv
try:
    from dotenv import load_dotenv
    load_dotenv(env_path)
    pw = os.environ.get("PG_PASSWORD","")
    print(f"\nAfter load_dotenv:")
    print(f"  PG_HOST     = {os.environ.get('PG_HOST','NOT SET')}")
    print(f"  PG_PORT     = {os.environ.get('PG_PORT','NOT SET')}")
    print(f"  PG_USER     = {os.environ.get('PG_USER','NOT SET')}")
    print(f"  PG_PASSWORD = {'*'*len(pw)} ({len(pw)} chars) {'✓' if pw else '✗ EMPTY'}")
    print(f"  PG_DB       = {os.environ.get('PG_DB','NOT SET')}")
except Exception as e:
    print(f"dotenv error: {e}")

# Try connecting
print("\nTrying connection...")
try:
    import psycopg2
    conn = psycopg2.connect(
        host=os.environ.get("PG_HOST","localhost"),
        port=int(os.environ.get("PG_PORT","5432")),
        user=os.environ.get("PG_USER","postgres"),
        password=os.environ.get("PG_PASSWORD",""),
        dbname="postgres"
    )
    print("✓ Connected successfully!")
    conn.close()
except Exception as e:
    print(f"✗ Failed: {e}")
