import sqlite3

DB_PATH = "malware_predictions.db"

def list_whitelisted_processes():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, process_name, absolute_path, whitelist_type, reason, added_by, created_at
        FROM whitelisted_apps
        WHERE is_active = 1
        ORDER BY created_at DESC
    """)
    rows = cursor.fetchall()
    if not rows:
        print("No active whitelisted processes found.")
    else:
        print("Active Whitelisted Processes:")
        for row in rows:
            print(f"ID: {row[0]}, Name: {row[1]}, Path: {row[2]}, Type: {row[3]}, Reason: {row[4]}, By: {row[5]}, Added: {row[6]}")
    conn.close()

if __name__ == "__main__":
    list_whitelisted_processes()