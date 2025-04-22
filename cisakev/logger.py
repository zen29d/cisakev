import logging
from logging.handlers import RotatingFileHandler
import os

# Default logging
LOG_DIR = "log"
LOG_FILENAME = "cisa_kev.log"

os.makedirs(LOG_DIR, exist_ok=True)
LOG_FILE = log_file = os.path.join(LOG_DIR, LOG_FILENAME)

def init_logger(log_file=LOG_FILE, console_quiet=False, logger_name=__name__, max_size=5*1024*1024, bk_count=3):
    logger = logging.getLogger(logger_name)
    logger.setLevel(logging.INFO)

    if not logger.handlers:
        # File handler
        file_handler =  RotatingFileHandler(log_file, mode='a', maxBytes=max_size, backupCount=bk_count)
        file_formatter = logging.Formatter('%(asctime)s %(levelname)s: %(message)s', '%y-%m-%d %H:%M:%S')
        file_handler.setFormatter(file_formatter)
        logger.addHandler(file_handler)

        # Console handler
        if not console_quiet:
            stream_handler = logging.StreamHandler()
            stream_formatter = logging.Formatter('%(levelname)s: %(message)s')
            stream_handler.setFormatter(stream_formatter)
            logger.addHandler(stream_handler)

    return logger