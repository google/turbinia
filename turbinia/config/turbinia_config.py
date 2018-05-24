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

from __future__ import unicode_literals


"""Turbinia Config Template"""

############
# TURBINIA #
############

# Turbinia Role as 'server' or 'psqworker'
ROLE = 'server'

# Which user account Turbinia runs as
USER = 'turbinia'

# Turbinia's installion directory
TURBINIA_DIR = '/opt/turbinia'

# GCSFuse mount for Turbinia scripts and logging.
# Note: this GCS instance is where Google Cloud Functions should
# be deployed to.
GCS_MOUNT_DIR = '/mnt/turbinia'

# Virtualenv directory
TURBINIAENV = '%s/turbinia-env' % TURBINIA_DIR

# Local directory for temporary data
TMP_DIR = '/var/tmp'

# 'PSQ' is currently the only valid option as
# a distributed task queue using Google Cloud Pub/Sub
TASK_MANAGER = 'PSQ'

# File to log to; set this as 'None' if log file is not desired
# By default, Turbinia logs are written to a directory (GCS_MOUNT_DIR) in the GCS mount
LOG_FILE = '%s/output/logs/turbinia.log' % GCS_MOUNT_DIR

# Default base output directory for worker results and evidence
# When running Turbinia locally, you can set this to, for example,
# %/turbinia_output' % TMP_DIR
OUTPUT_DIR = '%s/output' % GCS_MOUNT_DIR

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
# NFS or a SAN for Evidence objects.
SHARED_FILESYSTEM = False

# This will set debugging flags for processes executed by Tasks (for
# Tasks/binaries that support it).  This could cause performance issues with
# some tasks, so it is recommended to only set this to True when debugging
# problems.
DEBUG_TASKS = False


###############
# GCP AND GCE #
###############

PROJECT = 'None'
ZONE = 'None'
INSTANCE = 'None'
DEVICE_NAME = 'None'
SCRATCH_PATH = 'None'
# GCS bucket that has Turbinia-specific scripts and can be used to store logs.
BUCKET_NAME = 'None'
PSQ_TOPIC = 'turbinia-psq'
# TODO(beamcodeup): Per https://github.com/google/turbinia/issues/172, Cloud
# Functions are only available on us-central1. Thus, hardcoding this for now.
# Fix this when CF starts supporting more regions.
TURBINIA_REGION = 'us-central1'


# Topic Turbinia will listen on for new Artifact events. This is also used as
# the Turbinia instance/namespace as it is a unique string per Turbinia
# instance and Cloud Project.
PUBSUB_TOPIC = 'turbinia-pubsub'

# GCS Path to copy worker results and Evidence output to
# Otherwise, set this as 'None' if output will be stored locally.
GCS_OUTPUT_PATH = 'gs://%s/output' % BUCKET_NAME

# Which state manager to use
STATE_MANAGER = 'Datastore'

REDIS_HOST = 'None'
REDIS_PORT = 'None'
TIMESKETCH_HOST = 'None'
TIMESKETCH_USER = 'None'
TIMESKETCH_PASSWORD = 'None'
