import logging
import sys

def setup_logger(name='honeypot', log_file='honeypot.log', level=logging.INFO):
    """Function to setup as many loggers as you want"""
    formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
    
    handler = logging.FileHandler(log_file)        
    handler.setFormatter(formatter)

    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)

    logger = logging.getLogger(name)
    logger.setLevel(level)
    logger.addHandler(handler)
    logger.addHandler(console_handler)

    # Add Database Handler
    try:
        from .db import DBHandler, DBLoggingHandler
        db_handler = DBHandler()
        db_logging_handler = DBLoggingHandler(db_handler)
        db_logging_handler.setFormatter(formatter)
        logger.addHandler(db_logging_handler)
    except Exception as e:
        print(f"Failed to setup database logging: {e}")

    # Add JSON File Handler
    try:
        import json
        import os
        
        class JSONLoggingHandler(logging.Handler):
            def __init__(self, log_dir='logs'):
                super().__init__()
                self.log_dir = log_dir
                if not os.path.exists(log_dir):
                    os.makedirs(log_dir)
                self.log_file = os.path.join(log_dir, 'honeypot.json')

            def emit(self, record):
                try:
                    log_entry = {
                        'timestamp': self.formatter.formatTime(record),
                        'level': record.levelname,
                        'service': record.name,
                        'message': record.getMessage(),
                    }
                    
                    # Extract IP if possible (similar to DB handler)
                    if "from" in record.getMessage():
                        parts = record.getMessage().split("from")
                        if len(parts) > 1:
                            log_entry['source_ip'] = parts[1].strip().split(":")[0]

                    with open(self.log_file, 'a') as f:
                        f.write(json.dumps(log_entry) + '\n')
                except Exception:
                    self.handleError(record)

        json_handler = JSONLoggingHandler()
        json_handler.setFormatter(formatter)
        logger.addHandler(json_handler)

    except Exception as e:
        print(f"Failed to setup JSON logging: {e}")

    return logger
