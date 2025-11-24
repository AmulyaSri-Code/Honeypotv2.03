import typesense
import mysql.connector
import time
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('indexer')

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

def init_typesense():
    try:
        schema = {
            'name': 'logs',
            'fields': [
                {'name': 'id', 'type': 'string'},
                {'name': 'service', 'type': 'string'},
                {'name': 'message', 'type': 'string'},
                {'name': 'source_ip', 'type': 'string', 'optional': True},
                {'name': 'timestamp', 'type': 'int64'}
            ],
            'default_sorting_field': 'timestamp'
        }
        try:
            client.collections['logs'].retrieve()
            logger.info("Collection 'logs' already exists.")
        except typesense.exceptions.ObjectNotFound:
            client.collections.create(schema)
            logger.info("Created collection 'logs'.")
    except Exception as e:
        logger.error(f"Failed to init Typesense: {e}")

def index_logs():
    last_id = 0
    while True:
        try:
            cnx = mysql.connector.connect(**DB_CONFIG)
            cursor = cnx.cursor(dictionary=True)
            
            cursor.execute("SELECT * FROM logs WHERE id > %s ORDER BY id ASC LIMIT 100", (last_id,))
            rows = cursor.fetchall()
            
            if rows:
                documents = []
                for row in rows:
                    doc = {
                        'id': str(row['id']),
                        'service': row['service'],
                        'message': row['message'],
                        'source_ip': row['source_ip'] if row['source_ip'] else '',
                        'timestamp': int(row['timestamp'].timestamp())
                    }
                    documents.append(doc)
                    last_id = row['id']
                
                client.collections['logs'].documents.import_(documents, {'action': 'upsert'})
                logger.info(f"Indexed {len(documents)} logs. Last ID: {last_id}")
            
            cursor.close()
            cnx.close()
        except Exception as e:
            logger.error(f"Indexing error: {e}")
        
        time.sleep(5)

if __name__ == "__main__":
    time.sleep(5) # Wait for Typesense to start
    init_typesense()
    index_logs()
