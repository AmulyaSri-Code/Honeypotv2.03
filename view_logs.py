"""View honeypot logs from the database."""
import sqlite3
import sys

def main():
    conn = sqlite3.connect("honeypot.db")
    conn.row_factory = sqlite3.Row
    
    print("\n=== CONNECTIONS ===\n")
    for row in conn.execute("""
        SELECT id, ip, port, service, timestamp, country, city, session_duration_sec
        FROM connections ORDER BY id DESC LIMIT 50
    """):
        geo = f"{row['country'] or 'N/A'}/{row['city'] or 'N/A'}"
        print(f"  {row['id']:4} | {row['ip']:15} | {row['service']:6} | {geo:25} | {row['timestamp']} | {row['session_duration_sec'] or 0}s")
    
    print("\n=== COMMANDS (with ML attack classification) ===\n")
    try:
        rows = conn.execute("""
            SELECT id, ip, service, command, timestamp, attack_category
            FROM commands ORDER BY id DESC LIMIT 50
        """).fetchall()
    except sqlite3.OperationalError:
        rows = conn.execute("""
            SELECT id, ip, service, command, timestamp
            FROM commands ORDER BY id DESC LIMIT 50
        """).fetchall()
    for row in rows:
        r = dict(row)
        cmd = (r.get('command') or '')[:50]
        atk = r.get('attack_category') or '-'
        print(f"  {r.get('id', ''):4} | {r.get('ip', ''):15} | {r.get('service', ''):6} | {atk:22} | {cmd}")
    
    conn.close()

if __name__ == "__main__":
    main()
