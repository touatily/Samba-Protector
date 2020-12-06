import conf
import logging
import sys

logger = logging.getLogger('wishare_protector')

level = {"DEBUG":logging.DEBUG, "INFO":logging.INFO, "WARNING":logging.WARNING,
            "ERROR":logging.ERROR, "CRITICAL":logging.CRITICAL}

if conf.config.loaded:
    logger.setLevel(level[conf.config.log_level])
    ch = logging.FileHandler(conf.config.logfile, mode='a')
else:
    ch = logging.StreamHandler()
    logger.setLevel(logging.DEBUG)

ch.setLevel(logging.DEBUG)

formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
ch.setFormatter(formatter)
logger.addHandler(ch)

# now we can log lines usging:
#   - logger.debug('debug message')
#   - logger.info('info message')
#   - logger.warning('warn message')
#   - logger.error('error message')
#   - logger.critical('critical message')

# Sample line log:
# 2020-09-29 17:03:59,245 - wishare_protector - DEBUG - debug message
