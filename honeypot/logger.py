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

    return logger
