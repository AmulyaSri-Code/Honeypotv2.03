import uuid
import time

class SessionManager:
    def __init__(self):
        self.sessions = {}

    def create_session(self, ip, service_type):
        """Creates a new session for an incoming connection."""
        session_id = str(uuid.uuid4())[:8]  # Short unique ID
        self.sessions[session_id] = {
            "ip": ip,
            "service": service_type,
            "start_time": time.time(),
            "commands": []
        }
        return session_id

    def get_session(self, session_id):
        return self.sessions.get(session_id)

    def end_session(self, session_id):
        if session_id in self.sessions:
            del self.sessions[session_id]
