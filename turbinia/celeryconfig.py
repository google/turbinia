# -*- coding: utf-8 -*-
# Copyright 2017 Google Inc.
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
"""Celery confguration.

Sets configuration for the Turbinia Celery components.
"""
from turbinia import config

config.LoadConfig()

accept_content = ['json']
broker_connection_retry_on_startup = True
# Store Celery task results metadata
result_backend = config.CELERY_BACKEND
task_default_queue = config.INSTANCE_ID
# Re-queue task if Celery worker abruptly exists
task_reject_on_worker_lost = True
task_track_started = True
worker_cancel_long_running_tasks_on_connection_loss = True
worker_concurrency = 1
worker_prefetch_multiplier = 1
# Avoid task duplication
worker_deduplicate_successful_tasks = True
