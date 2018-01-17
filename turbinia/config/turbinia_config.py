# -*- coding: utf-8 -*-
# Copyright 2016 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the 'License');
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an 'AS IS' BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from __future__ import unicode_literals


"""Turbinia Config Template"""

###################
# Turbinia Config #
###################

# Which user account Turbinia runs as
USER = 'turbinia'

# Turbina's home directory
# TODO(beamupcode): Do we need this?
HOME_DIR = '/home/%s' % USER

# Turbinia source code directory (local git repository)
SRC_DIR = '%s/src' % HOME_DIR

# Turbinia CLI
TURBINIACTL = '%s/turbinia/turbiniactl' % SRC_DIR

# Virtualenv directory
TURBINIAENV = '%s/turbinia-env' % HOME_DIR

# Virtualenv activator
VIRTUALENV_ACTIVATE = '%s/bin/activate' % TURBINIAENV

# GCS bucket that has Turbinia-specific scripts and
# that can be used to store logs.
BUCKET = 'turbinia'

# GCS mount for Turbinia-specific scripts and logging
MOUNT_POINT = '/mnt/turbinia'

# Default output directory
# Turbinia logs are written to a directory in the GCS mount
OUTPUT_DIR = '%s/output' % MOUNT_POINT

# Local directory for temporary data
TMP_DIR = '/var/tmp'

# 'PSQ' is currently the only valid option
# a distributed task queue using Google Cloud Pub/Sub
TASK_MANAGER = 'PSQ'

# File to log to
# Set this as None if log file is not desired
LOG_FILE = None

# Time to sleep in task management loops
SLEEP_TIME = 10

# True if running as a single run, or False if keeping server running indefinitely
SINGLE_RUN = False

# Local directory in the worker to put other mount directories for locally
# mounting images/disks
MOUNT_DIR_PREFIX = '/mnt/turbinia-mounts'

# This indicates whether the workers are running in an environment with a shared
# filesystem. This should be False for environments with workers running in
# GCE, and True for environments that have workers on dedicated machines with
# NFS or a SAN for Evidence objects.
SHARED_FILESYSTEM = False

#####################
# GCE configuration #
#####################
PROJECT = None
ZONE = None
INSTANCE = None
DEVICE_NAME = None
SCRATCH_PATH = None
BUCKET_NAME = 'turbinia'
PSQ_TOPIC = 'turbinia-psq'

# Topic Turbinia will listen on for new Artifact events. This is also used as
# the Turbinia instance/namespace as it is a unique string per Turbinia
# instance and Cloud Project.
PUBSUB_TOPIC = 'turbinia-pubsub'

# GCS Path to copy worker results and Evidence output to
# TIP: It's not recommended to use the existing GCS used for scripts and
# logging. Maintain separation of concern.
GCS_OUTPUT_PATH = None

# Which state manager to use
STATE_MANAGER = 'Datastore'
