from fastapi import FastAPI, WebSocket, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
import mysql.connector
import json
import asyncio
from datetime import datetime
import os

app = FastAPI()

# Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Serve Static Files (Frontend)
frontend_dist = os.path.join(os.path.dirname(__file__), "frontend/dist")
if os.path.exists(frontend_dist):
    app.mount("/assets", StaticFiles(directory=os.path.join(frontend_dist, "assets")), name="assets")

@app.get("/")
async def serve_frontend():
    if os.path.exists(os.path.join(frontend_dist, "index.html")):
        return FileResponse(os.path.join(frontend_dist, "index.html"))
    return {"message": "Frontend not built or found"}

# MySQL Config
DB_CONFIG = {
    'host': 'localhost',
    'user': 'honeypot',
    'password': 'honeypot_password',
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

# Search endpoint removed (Typesense deprecated)

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
    last_id = 0
    
    # Initialize last_id to current max to avoid flooding old logs
    try:
        cnx = mysql.connector.connect(**DB_CONFIG)
        cursor = cnx.cursor(dictionary=True)
        cursor.execute("SELECT MAX(id) as max_id FROM logs")
        row = cursor.fetchone()
        if row and row['max_id']:
            last_id = row['max_id']
        cursor.close()
        cnx.close()
    except Exception:
        pass

    try:
        while True:
            # Poll DB for NEW logs
            try:
                cnx = mysql.connector.connect(**DB_CONFIG)
                cursor = cnx.cursor(dictionary=True)
                cursor.execute("SELECT * FROM logs WHERE id > %s ORDER BY id ASC", (last_id,))
                new_logs = cursor.fetchall()
                cursor.close()
                cnx.close()
                
                for log in new_logs:
                    if isinstance(log['timestamp'], datetime):
                        log['timestamp'] = log['timestamp'].isoformat()
                    await websocket.send_json(log)
                    last_id = log['id']
                    
            except Exception as e:
                print(f"WS Error: {e}")
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
