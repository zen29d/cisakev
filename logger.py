import logging
import os

# Default logging
LOG_DIR = "log"
LOG_FILENAME = "cisa_kev.log"

os.makedirs(LOG_DIR, exist_ok=True)
LOG_FILE = log_file = os.path.join(LOG_DIR, LOG_FILENAME)

def init_logger(log_file = LOG_FILE, console_quiet=False, logger_name = __name__):
    logger = logging.getLogger(logger_name)
    logger.setLevel(logging.INFO)

    if not logger.handlers:
        # File handler
        file_handler = logging.FileHandler(log_file, mode='a')
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