import logging
from logging.handlers import RotatingFileHandler
import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import Base

# Log file size 5 MB
LOG_SIZE = 5*1024*1024
BK_COUNT = 3

def init_logger(log_file=Base.LOG_FILE, console_quiet=False, logger_name=__name__):
    logger = logging.getLogger(logger_name)
    logger.setLevel(logging.INFO)

    if not logger.handlers:
        # File log handler
        file_handler =  RotatingFileHandler(log_file, mode='a', maxBytes=LOG_SIZE, backupCount=BK_COUNT)
        file_formatter = logging.Formatter('%(asctime)s %(levelname)s: %(message)s', '%y-%m-%d %H:%M:%S')
        file_handler.setFormatter(file_formatter)
        logger.addHandler(file_handler)

        # Console log handler
        if not console_quiet:
            stream_handler = logging.StreamHandler()
            stream_formatter = logging.Formatter('%(levelname)s: %(message)s')
            stream_handler.setFormatter(stream_formatter)
            logger.addHandler(stream_handler)

    return logger