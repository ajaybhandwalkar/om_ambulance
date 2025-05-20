import logging
import os
import sys
from pythonjsonlogger.json import JsonFormatter

def init_logger():
    log_level = os.getenv('LOGLEVEL', 'info').upper()
    formatter = JsonFormatter(
        '%(asctime)s %(name)s[%(process)d]: %(levelname)s - %(message)s')
    log = logging.getLogger('om_ambulance')
    if not log.hasHandlers():
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(formatter)
        log.addHandler(console_handler)
        log.setLevel(log_level)
    return log


if __name__ == '__main__':
    log = init_logger()