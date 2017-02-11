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
# Valid values are 'PubSub' or 'Celery'
TASK_MANAGER = 'PubSub'
# Time between heartbeats in seconds
WORKER_HEARTBEAT = 600
# Timeout between heartbeats for Workers to be considered inactive
WORKER_TIMEOUT = 3600

# GCE configuration
PROJECT = None
ZONE = None
INSTANCE = None
DEVICE_NAME = None
SCRATCH_PATH = None
BUCKET_NAME = None
PUBSUB_SERVER_TOPIC = None
PUBSUB_WORKER_TOPIC = None
PUBSUB_TASK_TOPIC = None

# Redis configuration
REDIS_HOST = None
REDIS_PORT = None

# Timesketch configuration
TIMESKETCH_HOST = None
TIMESKETCH_USER = None
TIMESKETCH_PASSWORD = None
