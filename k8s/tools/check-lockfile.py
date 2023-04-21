# This script tries to acquire a lock on the worker using
# a timeout equal to the maximum job timeout. It will return
# if a lock can be acquired or the lock process times out.
# It can be used in container orchestration setups (eg k8s)
# to make sure workers terminate gracefully.

import filelock
import logging

from turbinia import config
from turbinia.config import logger

log = logging.getLogger('turbinia')
logger.setup()
log.setLevel(logging.DEBUG)


def main():
  config.LoadConfig()
  max_timeout = 0
  for values in config.DEPENDENCIES:
    timeout = values.get('timeout')
    if timeout > max_timeout:
      max_timeout = timeout
  log.debug(f'[check-lockfile] Set max timeout: {max_timeout}')
  try:
    lock = filelock.FileLock(config.LOCK_FILE)
    log.debug(f'[check-lockfile] Acquiring lock {config.LOCK_FILE}')
    with lock.acquire(timeout=max_timeout):
      log.debug(f'[check-lockfile] Lock {config.LOCK_FILE} acquired')
  except filelock.Timeout:
    log.debug(f'[check-lockfile] Lock {config.LOCK_FILE} timed out')
    return
  log.debug(f'[check-lockfile] Lock {config.LOCK_FILE} released')


if __name__ == '__main__':
  main()
