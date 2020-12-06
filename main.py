#!/usr/bin/env python3
import signal
import sys
import conf
import argparse

# loading configuration
parser = argparse.ArgumentParser(prog="WishareProtector", description='WishareProtector to protect wishare.')
parser.add_argument('--config', nargs=1, metavar='filename', type=str, required=True, help='Configuration file path')
args = parser.parse_args()
try:
    conf.config.loadConfig(args.config[0])
except Exception as e:
    print("Error loading configuration:", e)
    sys.exit()

import analyzer as anlz
import logger as log

def handler(signum, frame):
    log.logger.critical(f'wishareprotector received signal: [{signum}]')
    log.logger.info("Service wishareprotector terminating ... ")
    sys.exit()

log.logger.info("Service wishareprotector starting ... ")
log.logger.info(f"Configuration loaded \"{sys.argv[1]}\"")

# handle signals
signal.signal(signal.SIGABRT, handler)
signal.signal(signal.SIGINT, handler)
signal.signal(signal.SIGTERM, handler)

log.logger.info(f"Configuration contains \"{len(conf.config.policies)}\" policies")
log.logger.info(f"Log level is set to {conf.config.log_level}")

anlz.analyzer.mainloop()
