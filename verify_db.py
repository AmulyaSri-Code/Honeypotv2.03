import mysql.connector

config = {
    'host': 'localhost',
    'user': 'root',
    'password': 'password',
    'database': 'honeypot_logs'
}

try:
    cnx = mysql.connector.connect(**config)
    cursor = cnx.cursor()
    cursor.execute("SELECT * FROM logs ORDER BY id DESC LIMIT 5")
    for (id, timestamp, service, level, message, source_ip, details) in cursor:
        print(f"Log: {id} | {service} | {message}")
    cursor.close()
    cnx.close()
except mysql.connector.Error as err:
    print(f"Error: {err}")
