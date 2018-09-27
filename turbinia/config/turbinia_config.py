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

from __future__ import unicode_literals


# Turbinia Role as 'server' or 'psqworker'
ROLE = 'server'

# Which user account Turbinia runs as
USER = 'turbinia'

# Turbinia's installation directory
TURBINIA_DIR = '/opt/turbinia'

# 'PSQ' is currently the only valid option as
# a distributed task queue using Google Cloud Pub/Sub
TASK_MANAGER = 'PSQ'

# Default base output directory for worker results and evidence.
OUTPUT_DIR = '/var/tmp'

# File to log to; set this as None if log file is not desired
# By default, Turbinia logs are written to a directory (GCS_OUTPUT_DIR)
# in the GCS mount
LOG_FILE = '%s/turbinia.log' % OUTPUT_DIR

# Path to a lock file used for the worker tasks.
LOCK_FILE = '%s/turbinia-worker.lock' % OUTPUT_DIR

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


###############################
# Google Cloud Platform (GCP) #
###############################

# GCP project, region and zone where Turbinia will run.  Note that Turbinia does
# not currently support multi-zone operation.  Even if you are running Turbinia
# in Hybrid mode (with the Server and Workers running on local machines), you
# will still need to provide these three parameters.
# TODO(aarontp): Refactor these (and *PATH) var names to be consistent
PROJECT = 'None'
ZONE = 'None'
TURBINIA_REGION = 'None'

# GCS bucket that has Turbinia specific scripts and can be used to store logs.
# This must be globally unique within GCP.
BUCKET_NAME = 'None'

# This is the internal PubSub topic that PSQ will use.  This should be different
# than the PUBSUB_TOPIC variable.  The actual PubSub topic created will be this
# variable prefixed with 'psq-'.
PSQ_TOPIC = 'turbinia-psq'

# A unique ID per Turbinia instance. Used to namespace datastore entries.
INSTANCE_ID = 'turbinia-pubsub'

# Topic Turbinia will listen on for new requests.  This should be different than
# the PSQ_TOPIC variable.
PUBSUB_TOPIC = INSTANCE_ID

# GCS Path to copy worker results and Evidence output to
# Otherwise, set this as 'None' if output will be stored locally.
GCS_OUTPUT_PATH = 'gs://%s/output' % BUCKET_NAME

# Which state manager to use
STATE_MANAGER = 'Datastore'


##########
# CELERY #
##########

# Method for communication between nodes
CELERY_BROKER = 'None'

# Storage for task results/status
CELERY_BACKEND = 'None'

# Can be the same as CELERY_BROKER
KOMBU_BROKER = 'None'

# Used to namespace communications.
KOMBU_CHANNEL = '%s-kombu' % INSTANCE_ID

# Will messages be persistent and require acknowledgment?
# http://docs.celeryproject.org/projects/kombu/en/4.0/reference/kombu.html#kombu.Connection.SimpleBuffer
KOMBU_DURABLE = True

# Use Redis for state management
REDIS_HOST = 'None'
REDIS_PORT = 'None'
REDIS_DB = 'None'
