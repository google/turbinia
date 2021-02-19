s/PROMETHEUS_ENABLED = .*/PROMETHEUS_ENABLED = False/g
s/STATE_MANAGER = .*/STATE_MANAGER = 'Datastore'/g
s/TASK_MANAGER = .*/TASK_MANAGER = 'PSQ'/g
s/PUBSUB_TOPIC = .*/PUBSUB_TOPIC = 'turbinia-dev'/g
s/OUTPUT_DIR = .*/OUTPUT_DIR = '\/evidence'/g
s/GCS_OUTPUT_PATH = .*/GCS_OUTPUT_PATH = 'gs:\/\/%s\/output' % BUCKET_NAME/g
s/MOUNT_DIR_PREFIX = .*/MOUNT_DIR_PREFIX = '\/tmp\/turbinia-mounts'/g
s/SHARED_FILESYSTEM = .*/SHARED_FILESYSTEM = True/g
s/DEBUG_TASKS = .*/DEBUG_TASKS = True/g
s/DISABLED_JOBS = .*/DISABLED_JOBS = ['VolatilityJob', 'DockerContainersEnumerationJob', 'PhotorecJob']/g
