from turbinia import config

config.LoadConfig()

accept_content = ['json']
broker_connection_retry_on_startup = True
# Store Celery task results metadata
result_backend = config.CELERY_BACKEND
task_default_queue = config.INSTANCE_ID
# Re-queue task if Celery worker abruptly exists
task_reject_on_worker_lost = True
task_track_started = True
worker_cancel_long_running_tasks_on_connection_loss = True
worker_concurrency = 1
worker_prefetch_multiplier = 1
# Avoid task duplication
worker_deduplicate_successful_tasks = True
