import celery

from turbinia import celeryconfig
from turbinia import config
from turbinia import debug
from turbinia import task_utils

config.LoadConfig()

config.TURBINIA_COMMAND = 'celeryworker'
debug.initialize_debugmode_if_requested()

app = celery.Celery(
    'turbinia', broker=config.CELERY_BROKER, backend=config.CELERY_BACKEND)
app.config_from_object(celeryconfig)
app.autodiscover_tasks()
app.task(task_utils.task_runner, name='task_runner')

if __name__ == '__main__':
  app.start()
