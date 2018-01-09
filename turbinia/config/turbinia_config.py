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

import os
import json

# Turbinia Config

# set config values below and then comment out, delete, or set to False
UNCONFIGURED = True

# 'PSQ' is currently the only valid option
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

# This indicates whether the workers are running in an environment with a shared
# filesystem.  This should be False for environments with workers running in
# GCE, and True for environments that have workers on dedicated machines with
# NFS or a SAN for Evidence objects.
SHARED_FILESYSTEM = False

# GCE configuration
PROJECT = None
ZONE = None
INSTANCE = None
DEVICE_NAME = None
SCRATCH_PATH = None
BUCKET_NAME = None
PSQ_TOPIC = u'turbinia-psq'

GCE_SERVICE_ACCOUNT = 'turbinia-mgr'
GCE_SERVICE_ACCOUNT_KEYS_FILE = '../../../../../etc/%s-keys.json' % GCE_SERVICE_ACCOUNT

GCE_SSH_KEY_FILE = '%s/.ssh/google_compute_engine' % os.getenv('HOME')
GCE_INSTANCE_NAME_PREFIX = None
GCE_IMAGE_FAMILY = 'debian-9'
GCE_IMAGE_PROJECT = 'debian-cloud'
GCE_BOOT_DISK_SIZE = '200GB'

GCE_REQUIRED_ROLES = ['roles/datastore.user',
                      'roles/pubsub.editor',
                      'roles/storage.objectAdmin',
                      'roles/compute.instanceAdmin',]

GCE_REQUIRED_SERVICES = ['pubsub.googleapis.com',
                         'cloudfunctions.googleapis.com',
                         'datastore.googleapis.com',]

GCE_SERVER_INSTANCE = 'turbinia-server'

GCE_WORKER_INSTANCE = 'turbinia-worker'
GCE_WORKER_POOL_SIZE = 2

# Topic Turbinia will listen on for new Artifact events.  This is also used as
# the Turbinia instance/namespace as it is a unique string per Turbinia
# instance and Cloud Project.
PUBSUB_TOPIC = None

# GCS Path to copy worker results and Evidence output to
GCS_OUTPUT_PATH = False

# Which state manager to use
STATE_MANAGER = u'Datastore'
