# -*- coding: utf-8 -*-
# Copyright 2016 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Turbinia Config Template"""

################################################################################
#                          Base Turbinia configuration
#
# All options in this section are required to be set to non-empty values.
################################################################################

# A unique ID per Turbinia instance. Used to keep multiple Turbinia instances
# separate when running with the same Cloud projects or backend servers.
INSTANCE_ID = 'turbinia-instance1'

# Which state manager to use. Valid options are 'Datastore' or 'Redis'.  Use
# 'Datastore' for Cloud (GCP) or hybrid installations, and 'Redis' for local
# installations.
STATE_MANAGER = 'Datastore'

# Which Task manager to use. Valid options are 'PSQ' and 'Celery'.  Use 'PSQ'
# for Cloud (GCP) or hybrid installations, and 'Celery' for local
# installations.
TASK_MANAGER = 'PSQ'

# Default base output directory for worker results and evidence.
OUTPUT_DIR = '/var/tmp'

# Directory for temporary files.  Some temporary files can be quite large (e.g.
# Plaso files can easily be multiple gigabytes), so make sure there is enough
# space.  Nothing from this directory will be saved.  This directory should be
# different from the OUTPUT_DIR.
TMP_DIR = '/tmp'

# Default path to where logs will be stored. Note for a Kubernetes
# environment, change the path to the shared path configured for Filestore
# so that logs are can be easily retrieved from one central location.
LOG_DIR = '/var/tmp'

# Path to a lock file used for the worker tasks.
LOCK_FILE = '%s/turbinia-worker.lock' % TMP_DIR

# This folder is used to maintain the RESOURCE_FILE needed for resource tracking across
# multiple workers on a given host. It is important that this folder is shared amongst
# all workers running ont he same host to prevent resource locking issues!
TMP_RESOURCE_DIR = '/var/run/lock'

# Path to a resource state file used for tracking shared Evidence types. This should
# be a shared path amongst all workers on a given host to properly update the state.
# If for example, you are running the workers within containers, be sure to map the
# OUTPUT_DIR from the container to the host so that the workers are updating a single
# resource file rather than individual state files within the containers.
RESOURCE_FILE = '%s/turbinia-state.json' % TMP_RESOURCE_DIR

# Path to a resource state lock file used for locking changes to shared Evidence types.
# Similar to RESOURCE_FILE, this should be a shared path amongst all workers on a given
# host to properly lock the resource state file.
RESOURCE_FILE_LOCK = '%s.lock' % RESOURCE_FILE

# For Kubernetes infrastructure. Indicates whether a given pod is set to be deleted.
SCALEDOWN_WORKER_FILE = '%s/turbinia-to-scaledown.lock' % TMP_DIR

# Time in seconds to sleep in task management loops
SLEEP_TIME = 10

# Whether to run as a single run, or to keep server running indefinitely
SINGLE_RUN = False

# Local directory in the worker to put other mount directories for locally
# mounting images/disks
MOUNT_DIR_PREFIX = '/mnt/turbinia-mounts'

# This indicates whether the workers are running in an environment with a shared
# filesystem.  This should be False for environments with workers running in
# GCE, and True for environments that have workers on dedicated machines with
# NFS or a SAN for storing Evidence objects.
SHARED_FILESYSTEM = False

# This will set debugging flags for processes executed by Tasks (for
# Tasks/binaries that support it).  This could cause performance issues with
# some tasks, so it is recommended to only set this to True when debugging
# problems.
DEBUG_TASKS = False

# Directory keeping all eligible recipes
RECIPE_FILE_DIR = None

################################################################################
#                         External Dependency Configurations
#
# Options in this section are used to configure system and docker dependencies.
################################################################################

# This will allow for the configuration of system dependencies and docker
# containers. The following configuration will need to be set per job config.
# Please use the example below as a guide to add additional job checks.
# {
#   'job': 'MyJob'
#   'programs': ['list', 'of', 'required', 'programs']
#   'docker_image': 'ImageID' # Or None if no image configured for this job.
# }

# This will enable the usage of docker containers for the worker.
DOCKER_ENABLED = False

# Any Jobs added to this list will be disabled by default at start-up.  See the
# output of `turbiniactl listjobs` for a complete list of Jobs.  Job names
# entered here are case insensitive, but must be quoted.  Disabled Jobs can
# still be enabled with the --jobs_allowlist flag on the server, but the client
# will not be able to allowlist jobs that have been disabled or denylisted on
# the server.
DISABLED_JOBS = ['BinaryExtractorJob', 'BulkExtractorJob', 'DfdeweyJob', 'HindsightJob', 'PhotorecJob']  # yapf: disable

# Configure additional job dependency checks below.
DEPENDENCIES = [{
    'job': 'BinaryExtractorJob',
    'programs': ['image_export.py'],
    'docker_image': None,
    'timeout': 7200
}, {
    'job': 'BulkExtractorJob',
    'programs': ['bulk_extractor'],
    'docker_image': None,
    'timeout': 14400
}, {
    'job': 'DfdeweyJob',
    'programs': ['dfdewey'],
    'docker_image': None,
    'timeout': 86400
}, {
    'job': 'DockerContainersEnumerationJob',
    'programs': ['de.py'],
    'docker_image': None,
    'timeout': 1200
}, {
    'job': 'FileSystemTimelineJob',
    'programs': ['list_file_entries.py'],
    'docker_image': None,
    'timeout': 1800
}, {
    'job': 'FsstatJob',
    'programs': ['fsstat'],
    'docker_image': None,
    'timeout': 1800
}, {
    'job': 'GitlabJob',
    'programs': ['zgrep'],
    'docker_image': None,
    'timeout': 1800
}, {
    'job': 'GrepJob',
    'programs': ['grep'],
    'docker_image': None,
    'timeout': 1800
}, {
    'job': 'HadoopAnalysisJob',
    'programs': ['strings'],
    'docker_image': None,
    'timeout': 1200
}, {
    'job': 'HindsightJob',
    'programs': ['hindsight.py'],
    'docker_image': None,
    'timeout': 1200
}, {
    'job': 'JenkinsAnalysisJob',
    'programs': ['hashcat'],
    'docker_image': None,
    'timeout': 1200
}, {
    'job': 'LinuxAccountAnalysisJob',
    'programs': ['hashcat'],
    'docker_image': None,
    'timeout': 1200
}, {
    'job': 'LokiAnalysisJob',
    'programs': ['/opt/loki/loki.py'],
    'docker_image': None,
    'timeout': 1200
}, {
    'job': 'PartitionEnumerationJob',
    'programs': ['bdemount', 'blockdev'],
    'docker_image': None,
    'timeout': 1200
}, {
    'job': 'PlasoJob',
    'programs': ['log2timeline.py'],
    'docker_image': None,
    'timeout': 86400
}, {
    'job': 'PhotorecJob',
    'programs': ['photorec'],
    'docker_image': None,
    'timeout': 14400
}, {
    'job': 'PsortJob',
    'programs': ['psort.py'],
    'docker_image': None,
    'timeout': 3600
}, {
    'job': 'StringsJob',
    'programs': ['strings'],
    'docker_image': None,
    'timeout': 3600
}, {
    'job': 'VolatilityJob',
    'programs': ['vol.py'],
    'docker_image': None,
    'timeout': 3600
}, {
    'job': 'WindowsAccountAnalysisJob',
    'programs': ['hashcat', 'secretsdump.py'],
    'docker_image': None,
    'timeout': 3600
}, {
    'job': 'WordpressCredsAnalysisJob',
    'programs': ['hashcat', 'grep', 'strings'],
    'docker_image': None,
    'timeout': 3600
}]

################################################################################
#                        Google Cloud Platform (GCP)
#
# Options in this section are required if the TASK_MANAGER is set to 'PSQ'.
################################################################################

# GCP project, region and zone where Turbinia will run.  Note that Turbinia does
# not currently support multi-zone operation.  Even if you are running Turbinia
# in Hybrid mode (with the Server and Workers running on local machines), you
# will still need to provide these three parameters.
TURBINIA_PROJECT = None
TURBINIA_ZONE = None
TURBINIA_REGION = None

# GCS bucket that has Turbinia specific scripts and can be used to store logs.
# This must be globally unique within GCP.
BUCKET_NAME = None

# This is the internal PubSub topic that PSQ will use.  This should be different
# than the PUBSUB_TOPIC variable.  The actual PubSub topic created will be this
# variable prefixed with 'psq-'.
PSQ_TOPIC = 'turbinia-psq'

# The PubSub topic Turbinia will listen on for new requests.  This should be
# different than the PSQ_TOPIC variable.
PUBSUB_TOPIC = INSTANCE_ID

# GCS Path to copy worker results and Evidence output to.
# Otherwise, set this as 'None' if output will be stored in shared storage.
# GCS_OUTPUT_PATH = 'gs://%s/output' % BUCKET_NAME
GCS_OUTPUT_PATH = None

# Set this to True if you would like to enable Google Cloud Stackdriver Logging.
STACKDRIVER_LOGGING = False

# Set this to True if you would like to enable Google Cloud Error Reporting.
STACKDRIVER_TRACEBACK = False

################################################################################
#                           Celery / Redis / Kombu
#
# Options in this section are required if TASK_MANAGER is set to 'Celery'
################################################################################

# Method for communication between nodes
CELERY_BROKER = 'redis://localhost'

# Storage for task results/status
CELERY_BACKEND = 'redis://localhost'

# Can be the same as CELERY_BROKER
KOMBU_BROKER = CELERY_BROKER

# Used to namespace communications.
KOMBU_CHANNEL = '%s-kombu' % INSTANCE_ID

# Will messages be persistent and require acknowledgment?
# http://docs.celeryproject.org/projects/kombu/en/4.0/reference/kombu.html#kombu.Connection.SimpleBuffer
KOMBU_DURABLE = True

# Use Redis for state management
REDIS_HOST = 'localhost'
REDIS_PORT = '6379'
REDIS_DB = '0'

################################################################################
#                           Email Config
#
# These options are required if you wish to use email notifications
################################################################################

# Will emails notifications be enabled
EMAIL_NOTIFICATIONS = False

# Host Address and port number(TLS)
EMAIL_HOST_ADDRESS = 'example.address.com'
EMAIL_PORT = 587

# Email address and password
EMAIL_ADDRESS = 'example@address.com'
EMAIL_PASSWORD = 'Hunter2'

###############################################################################
#                           Prometheus Config
#
# These options are required for customizing the prometheus configuration
###############################################################################
# This will enable the Prometheus service for the workers and server.
PROMETHEUS_ENABLED = True

# Prometheus listen address and port
PROMETHEUS_ADDR = '0.0.0.0'
PROMETHEUS_PORT = 9200

###############################################################################
#                           dfDewey Config
#
# These options are required for the dfDewey task
###############################################################################

# Postgres Config
DFDEWEY_PG_HOST = '127.0.0.1'
DFDEWEY_PG_PORT = 5432
DFDEWEY_PG_DB_NAME = 'dfdewey'

# OpenSearch Config
DFDEWEY_OS_HOST = '127.0.0.1'
DFDEWEY_OS_PORT = 9200
# OS_URL can be used to specify a RFC-1738 formatted URL
# Example: OS_URL = 'https://user:secret@127.0.0.1:9200/'
DFDEWEY_OS_URL = None
