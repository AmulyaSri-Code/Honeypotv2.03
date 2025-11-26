from fastapi import FastAPI, WebSocket, Request
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

# --- WebSocket Manager ---
class ConnectionManager:
    def __init__(self):
        self.active_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)

    async def broadcast(self, message: str):
        for connection in self.active_connections:
            await connection.send_text(message)

manager = ConnectionManager()
topology_manager = ConnectionManager()

@app.websocket("/ws/live")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            # Poll DB for latest log
            try:
                cnx = mysql.connector.connect(**DB_CONFIG)
                cursor = cnx.cursor(dictionary=True)
                cursor.execute("SELECT * FROM logs ORDER BY id DESC LIMIT 1")
                latest_log = cursor.fetchone()
                cursor.close()
                cnx.close()
                
                if latest_log:
                    if isinstance(latest_log['timestamp'], datetime):
                        latest_log['timestamp'] = latest_log['timestamp'].isoformat()
                    await websocket.send_json(latest_log)
            except Exception:
                pass
            await asyncio.sleep(2)
    except Exception:
        manager.disconnect(websocket)

@app.websocket("/ws/topology")
async def topology_endpoint(websocket: WebSocket):
    await topology_manager.connect(websocket)
    try:
        while True:
            # Build Topology Data
            # Nodes: Honeypot (Center) + Attackers
            # Edges: Attackers -> Honeypot
            try:
                cnx = mysql.connector.connect(**DB_CONFIG)
                cursor = cnx.cursor(dictionary=True)
                
                # Get recent unique IPs
                cursor.execute("SELECT DISTINCT source_ip, service FROM logs WHERE timestamp > NOW() - INTERVAL 10 MINUTE AND source_ip IS NOT NULL")
                rows = cursor.fetchall()
                cursor.close()
                cnx.close()

                nodes = [{"id": 1, "label": "Honeypot", "group": "server", "color": "#10B981"}] # Green
                edges = []
                
                for i, row in enumerate(rows):
                    attacker_id = i + 2
                    nodes.append({
                        "id": attacker_id, 
                        "label": row['source_ip'], 
                        "group": "attacker",
                        "color": "#EF4444" # Red
                    })
                    edges.append({
                        "from": attacker_id, 
                        "to": 1,
                        "label": row['service']
                    })

                topology_data = {"nodes": nodes, "edges": edges}
                await websocket.send_json(topology_data)
            except Exception as e:
                print(f"Topology error: {e}")
            
            await asyncio.sleep(5)
    except Exception:
        topology_manager.disconnect(websocket)

@app.post("/api/falco")
async def falco_webhook(request: Request):
    try:
        payload = await request.json()
        # Log Falco alert to DB or just print for now
        print(f"Received Falco Alert: {payload}")
        
        # You could also broadcast this to the live feed if you wanted
        # await manager.broadcast(json.dumps({"type": "alert", "data": payload}))
        
        return {"status": "received"}
    except Exception as e:
        return {"status": "error", "message": str(e)}
