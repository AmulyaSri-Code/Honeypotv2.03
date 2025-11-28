import mysql.connector
from mysql.connector import errorcode
import logging

logger = logging.getLogger('db_handler')

class DBHandler:
    def __init__(self, host='localhost', user='honeypot', password='honeypot_password', database='honeypot_logs'):
        self.config = {
            'host': host,
            'user': user,
            'password': password,
        }
        self.database = database
        self.init_db()

    def get_connection(self):
        try:
            return mysql.connector.connect(**self.config, database=self.database)
        except mysql.connector.Error as err:
            logger.error(f"Error connecting to database: {err}")
            return None

    def init_db(self):
        try:
            # Connect without database to create it if needed
            cnx = mysql.connector.connect(**self.config)
            cursor = cnx.cursor()
            try:
                cursor.execute(f"CREATE DATABASE IF NOT EXISTS {self.database}")
            except mysql.connector.Error as err:
                logger.error(f"Failed to create database: {err}")
                return
            finally:
                cursor.close()
                cnx.close()

            # Now connect to the specific database to create table
            cnx = self.get_connection()
            if cnx:
                cursor = cnx.cursor()
                table_query = """
                CREATE TABLE IF NOT EXISTS logs (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    service VARCHAR(50),
                    level VARCHAR(20),
                    message TEXT,
                    source_ip VARCHAR(45),
                    details JSON
                )
                """
                cursor.execute(table_query)
                cnx.commit()
                cursor.close()
                cnx.close()
                logger.info("Database initialized successfully")
        except Exception as e:
            logger.error(f"Database initialization failed: {e}")

    def insert_log(self, service, level, message, source_ip=None, details=None):
        cnx = self.get_connection()
        if cnx:
            try:
                cursor = cnx.cursor()
                query = "INSERT INTO logs (service, level, message, source_ip, details) VALUES (%s, %s, %s, %s, %s)"
                # Ensure details is a JSON string if provided
                import json
                details_json = json.dumps(details) if details else None
                
                cursor.execute(query, (service, level, message, source_ip, details_json))
                cnx.commit()
                cursor.close()
            except mysql.connector.Error as err:
                logger.error(f"Failed to insert log: {err}")
            finally:
                cnx.close()

class DBLoggingHandler(logging.Handler):
    def __init__(self, db_handler):
        super().__init__()
        self.db_handler = db_handler

    def emit(self, record):
        try:
            # Parse message to extract IP if possible, or pass it explicitly in extra
            # For now, we'll just log the message
            service = record.name
            level = record.levelname
            message = record.getMessage()
            
            # Try to extract IP from message if it follows standard format "from IP:PORT"
            source_ip = None
            if "from" in message:
                parts = message.split("from")
                if len(parts) > 1:
                    ip_part = parts[1].strip().split(":")[0]
                    # Basic IP validation could go here
                    source_ip = ip_part

            self.db_handler.insert_log(service, level, message, source_ip)
        except Exception:
            self.handleError(record)
