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

# Which Cloud provider to use. Valid options are 'Local' and 'GCP'. Use 'GCP'
# for GCP or hybrid installations, and 'Local' for local installations.
CLOUD_PROVIDER = 'Local'

# Task manager only supports 'Celery'.
TASK_MANAGER = 'Celery'

# Which state manager to use. The only valid option is 'Redis'.
STATE_MANAGER = 'Redis'

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
LOCK_FILE = f'{TMP_DIR}/turbinia-worker.lock'

# This folder is used to maintain the RESOURCE_FILE needed for resource tracking across
# multiple workers on a given host. It is important that this folder is shared amongst
# all workers running ont he same host to prevent resource locking issues!
TMP_RESOURCE_DIR = '/var/run/lock'

# Path to a resource state file used for tracking shared Evidence types. This should
# be a shared path amongst all workers on a given host to properly update the state.
# If for example, you are running the workers within containers, be sure to map the
# OUTPUT_DIR from the container to the host so that the workers are updating a single
# resource file rather than individual state files within the containers.
RESOURCE_FILE = f'{TMP_RESOURCE_DIR}/turbinia-state.json'

# Path to a resource state lock file used for locking changes to shared Evidence types.
# Similar to RESOURCE_FILE, this should be a shared path amongst all workers on a given
# host to properly lock the resource state file.
RESOURCE_FILE_LOCK = f'{RESOURCE_FILE}.lock'

# For Kubernetes infrastructure. Indicates whether a given pod is set to be deleted.
SCALEDOWN_WORKER_FILE = f'{TMP_DIR}/turbinia-to-scaledown.lock'

# Time in seconds to sleep in task management loops
SLEEP_TIME = 10

# Whether to run as a single run, or to keep server running indefinitely
# Note: This config var is deprecated and will be removed in the next release.
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

# This indicates whether the server and worker version need to be the same.
# Makes sense to set to False while developing.
VERSION_CHECK = True

# Directory keeping all eligible recipes
RECIPE_FILE_DIR = None

################################################################################
#                         Turbinia API Server configuration
#
# Options in this section are used to configure the API serrver.
################################################################################

# API server hostname or IP address to listen on
API_SERVER_ADDRESS = '0.0.0.0'

# API server port
API_SERVER_PORT = 8000

# Allowed CORS origins
API_ALLOWED_ORIGINS = ['http://localhost:8000']

# Enable/Disable API authentication. This will determine whether the API server will
# check for OAuth 2.0 bearer tokens in the 'Authorization' header.
API_AUTHENTICATION_ENABLED = False

# Chunk size in bytes for chunk reading when uploading evidences to server.
API_UPLOAD_CHUNK_SIZE = 1024

# Default path to where uploaded evidence will be stored on server.
API_EVIDENCE_UPLOAD_DIR = '/evidence'

# Max size in bytes for evidence uploaded to server.
API_MAX_UPLOAD_SIZE = 10737418240

# Path to Turbinia Web UI static files
WEBUI_PATH = '/web'

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
DISABLED_JOBS = ['VolatilityJob', 'BinaryExtractorJob', 'BulkExtractorJob', 'DfdeweyJob', 'HindsightJob', 'PhotorecJob']  # yapf: disable

# Configure additional job dependency checks below.
DEPENDENCIES = [{
    'job': 'BinaryExtractorJob',
    'programs': ['image_export'],
    'docker_image': None,
    'timeout': 7200
}, {
    'job': 'BulkExtractorJob',
    'programs': ['bulk_extractor'],
    'docker_image': None,
    'timeout': 14400
}, {
    'job': 'ContainerdEnumerationJob',
    'programs': ['/opt/container-explorer/bin/ce'],
    'docker_image': None,
    'timeout': 1200
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
    'job': 'FileArtifactExtractionJob',
    'programs': ['image_export'],
    'docker_image': None,
    'timeout': 1200
}, {
    'job': 'FileSystemTimelineJob',
    'programs': ['list_file_entries'],
    'docker_image': None,
    'timeout': 1800
}, {
    'job': 'FsstatJob',
    'programs': ['fsstat'],
    'docker_image': None,
    'timeout': 1800
}, {
    'job': 'GrepJob',
    'programs': ['grep'],
    'docker_image': None,
    'timeout': 1800
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
    'programs': ['hashcat', 'john'],
    'docker_image': None,
    'timeout': 1200
}, {
    'job': 'YaraAnalysisJob',
    'programs': ['/opt/fraken/fraken'],
    'docker_image': None,
    'timeout': 14400
}, {
    'job': 'PartitionEnumerationJob',
    'programs': ['bdemount', 'blockdev', 'fsapfsmount', 'luksdemount'],
    'docker_image': None,
    'timeout': 1200
}, {
    'job': 'PlasoJob',
    'programs': ['log2timeline', 'pinfo'],
    'docker_image': None,
    'timeout': 86400
}, {
    'job': 'PhotorecJob',
    'programs': ['photorec'],
    'docker_image': None,
    'timeout': 14400
}, {
    'job': 'PsortJob',
    'programs': ['psort'],
    'docker_image': None,
    'timeout': 14400
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
}, {
    'job': 'LLMAnalysisJob',
    'programs': [],
    'docker_image': None,
    'timeout': 3600
}, {
    'job': 'LLMArtifactsExtractionJob',
    'programs': [],
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

# GCS Path to copy worker results and Evidence output to.
# Otherwise, set this as 'None' if output will be stored in shared storage.
# GCS_OUTPUT_PATH = 'gs://%s/output' % BUCKET_NAME
GCS_OUTPUT_PATH = None

# Set this to True if you would like to enable Google Cloud Error Reporting.
STACKDRIVER_TRACEBACK = False

################################################################################
#                           Celery / Redis / Kombu
#
# Options in this section are required if TASK_MANAGER is set to 'Celery'
################################################################################

# Use Redis for state management
REDIS_HOST = 'localhost'
REDIS_PORT = '6379'
REDIS_DB = '0'

# Method for communication between nodes
CELERY_BROKER = f'redis://{REDIS_HOST}'

# Storage for task results/status
CELERY_BACKEND = f'redis://{REDIS_HOST}'

# Can be the same as CELERY_BROKER
KOMBU_BROKER = CELERY_BROKER

# Used to namespace communications.
KOMBU_CHANNEL = f'{INSTANCE_ID}-kombu'

# Will messages be persistent and require acknowledgment?
# http://docs.celeryproject.org/projects/kombu/en/4.0/reference/kombu.html#kombu.Connection.SimpleBuffer
KOMBU_DURABLE = True

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

###############################################################################
#                           GCP Gen-AI Configs
#
# These options are required for the VertexAI LLM analyzer
###############################################################################

# see https://ai.google.dev/tutorials/setup
GCP_GENERATIVE_LANGUAGE_API_KEY = ''

###############################################################################
#                           LLM Providers
#
# Specify the choosen LLm provider to be used with LLM analyzer
###############################################################################

# To add a new LLM provider, first add a new implementation class
# implementing turbinia.lib.llm_libs.llm_lib_base.TurbiniaLLMLibBase
# in a new module under turbinia.lib.llm_libs. Then extend the PROVIDERS_MAP
# in llm_client.py module with the provider name (as key) and
# implementationclass (as value).
# possible values ["vertexai"]
LLM_PROVIDER = 'vertexai'
