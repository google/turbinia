s/PROMETHEUS_ENABLED = .*/PROMETHEUS_ENABLED = False/g
s/STATE_MANAGER = .*/STATE_MANAGER = 'Redis'/g
s/TASK_MANAGER = .*/TASK_MANAGER = 'Celery'/g
s/OUTPUT_DIR = .*/OUTPUT_DIR = '\/evidence'/g
s/MOUNT_DIR_PREFIX = .*/MOUNT_DIR_PREFIX = '\/tmp\/turbinia-mounts'/g
s/SHARED_FILESYSTEM = .*/SHARED_FILESYSTEM = True/g
s/DEBUG_TASKS = .*/DEBUG_TASKS = True/g
s/DISABLED_JOBS = .*/DISABLED_JOBS = ['VolatilityJob', 'DockerContainersEnumerationJob', 'PhotorecJob']/g
