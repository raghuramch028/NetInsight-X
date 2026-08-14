import sqlite3

def inspect():
    db_path = "netinsight/database/netinsight.db"
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()

    cur.execute("SELECT name FROM sqlite_master WHERE type='table';")
    tables = [t[0] for t in cur.fetchall() if not t[0].startswith("sqlite_") and not t[0].startswith("django_") and not t[0].startswith("auth_")]

    print("=== NETINSIGHT.DB CORE APP TABLES ===")
    for table in tables:
        cur.execute(f"SELECT COUNT(*) FROM {table}")
        count = cur.fetchone()[0]
        print(f"\n[TABLE] Table: {table} (Total Rows: {count})")

        # Get column names
        cur.execute(f"PRAGMA table_info({table})")
        cols = [c[1] for c in cur.fetchall()]
        print(f"   Columns: {', '.join(cols)}")

        # Fetch top 3 sample rows
        cur.execute(f"SELECT * FROM {table} LIMIT 3")
        rows = cur.fetchall()
        for idx, row in enumerate(rows):
            print(f"   Row {idx+1}: {row}")

if __name__ == "__main__":
    inspect()
