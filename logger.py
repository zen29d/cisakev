import logging
import os

# Default logging
LOG_DIR = "log"
LOG_FILE = "cisa_kev.log"

def init_logger(log_dir=LOG_DIR, log_file=LOG_FILE, logger_name=__name__):
    os.makedirs(log_dir, exist_ok=True)
    log_path = os.path.join(log_dir, log_file)

    logger = logging.getLogger(logger_name)
    logger.setLevel(logging.INFO)

    if not logger.handlers:
        # File handler
        file_handler = logging.FileHandler(log_path, mode='a')
        file_formatter = logging.Formatter('%(asctime)s %(levelname)s: %(message)s', '%y-%m-%d %H:%M:%S')
        file_handler.setFormatter(file_formatter)
        logger.addHandler(file_handler)

        # Console handler
        stream_handler = logging.StreamHandler()
        stream_formatter = logging.Formatter('%(levelname)s: %(message)s')
        stream_handler.setFormatter(stream_formatter)
        logger.addHandler(stream_handler)

    return logger
