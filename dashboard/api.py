from fastapi import FastAPI, WebSocket
from fastapi.middleware.cors import CORSMiddleware
import typesense
import mysql.connector
import json
import asyncio
from datetime import datetime

app = FastAPI()

# Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Typesense Client
client = typesense.Client({
    'nodes': [{
        'host': 'localhost',
        'port': '8108',
        'protocol': 'http'
    }],
    'api_key': 'xyz',
    'connection_timeout_seconds': 2
})

# MySQL Config
DB_CONFIG = {
    'host': 'localhost',
    'user': 'root',
    'password': 'password',
    'database': 'honeypot_logs'
}

@app.get("/stats")
def get_stats():
    try:
        cnx = mysql.connector.connect(**DB_CONFIG)
        cursor = cnx.cursor(dictionary=True)
        
        # Total attacks
        cursor.execute("SELECT COUNT(*) as total FROM logs")
        total_attacks = cursor.fetchone()['total']
        
        # Attacks by service
        cursor.execute("SELECT service, COUNT(*) as count FROM logs GROUP BY service")
        by_service = cursor.fetchall()
        
        # Top IPs
        cursor.execute("SELECT source_ip, COUNT(*) as count FROM logs WHERE source_ip IS NOT NULL GROUP BY source_ip ORDER BY count DESC LIMIT 5")
        top_ips = cursor.fetchall()
        
        cursor.close()
        cnx.close()
        
        return {
            "total_attacks": total_attacks,
            "by_service": by_service,
            "top_ips": top_ips
        }
    except Exception as e:
        return {"error": str(e)}

@app.get("/search")
def search_logs(q: str = "*", page: int = 1):
    try:
        search_parameters = {
            'q': q,
            'query_by': 'message,service,source_ip',
            'sort_by': 'timestamp:desc',
            'page': page,
            'per_page': 10
        }
        return client.collections['logs'].documents.search(search_parameters)
    except Exception as e:
        return {"error": str(e)}

@app.websocket("/ws/live")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    try:
        while True:
            # In a real app, we'd use a pub/sub system. 
            # For now, we'll just poll the DB for the latest log every second
            try:
                cnx = mysql.connector.connect(**DB_CONFIG)
                cursor = cnx.cursor(dictionary=True)
                cursor.execute("SELECT * FROM logs ORDER BY id DESC LIMIT 1")
                latest_log = cursor.fetchone()
                cursor.close()
                cnx.close()
                
                if latest_log:
                    # Convert datetime to string
                    if isinstance(latest_log['timestamp'], datetime):
                        latest_log['timestamp'] = latest_log['timestamp'].isoformat()
                    await websocket.send_json(latest_log)
            except Exception:
                pass
            
            await asyncio.sleep(2)
    except Exception:
        pass
