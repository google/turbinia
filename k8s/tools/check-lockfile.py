import filelock
from turbinia import config


def main():
  max_timeout = 0
  for values in CONFIG.DEPENDENCIES:
    timeout = values.get('timeout')
    if timeout > max_timeout:
      max_timeout = timeout
  try:
    lock = filelock.FileLock(config.LOCK_FILE)
    with lock.acquire(timeout=max_timeout):
      return
  except filelock.Timeout:
    return


if __name__ == '__main__':
  main()
