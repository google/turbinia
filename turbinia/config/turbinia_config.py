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
"""Dummy Turbinia config file."""

# Turbinia Config
# Valid values are 'PSQ' or 'Celery'
TASK_MANAGER = u'PSQ'
# File to log to
LOG_FILE = None
# Default output directory
OUTPUT_DIR = None
# Time to sleep in task management loops
SLEEP_TIME = 10
# Whether to run as a single run, or to keep server running indefinitely
SINGLE_RUN = False
# Local directory in the worker to put other mount directories for locally
# mounting images/disks
MOUNT_DIR_PREFIX = u'/mnt/turbinia-mounts'

# GCE configuration
PROJECT = None
ZONE = None
INSTANCE = None
DEVICE_NAME = None
SCRATCH_PATH = None
BUCKET_NAME = None
PSQ_TOPIC = u'turbinia-psq'
# Topic Turbinia will listen on for new Artifact events
PUBSUB_TOPIC = None
# GCS Path to copy worker results and Evidence output to
GCS_OUTPUT_PATH = False

# Redis configuration
REDIS_HOST = None
REDIS_PORT = None

# Timesketch configuration
TIMESKETCH_HOST = None
TIMESKETCH_USER = None
TIMESKETCH_PASSWORD = None
