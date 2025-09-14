import sqlite3

DB_PATH = "static_detections.db"  # Change this to your actual DB file

def inspect_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # List all tables
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
    tables = [row[0] for row in cursor.fetchall()]
    if not tables:
        print("No tables found in the database.")
        return

    for table in tables:
        print(f"\n=== Table: {table} ===")
        # List fields/columns
        cursor.execute(f"PRAGMA table_info({table});")
        columns = [col[1] for col in cursor.fetchall()]
        print("Fields:", columns)

        # Show up to 5 rows of data
        cursor.execute(f"SELECT * FROM {table} LIMIT 5;")
        rows = cursor.fetchall()
        if rows:
            for row in rows:
                print(dict(zip(columns, row)))
        else:
            print("No data found in this table.")

    conn.close()

if __name__ == "__main__":
    inspect_db()