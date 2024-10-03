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
"""Celery worker app.

Configures and Starts the Turbinia Celery worker.
"""
import celery

from turbinia import celeryconfig
from turbinia import config
from turbinia import debug
from turbinia import task_utils

config.LoadConfig()

config.TURBINIA_COMMAND = 'celeryworker'
debug.initialize_debugmode_if_requested()

app = celery.Celery(
    'turbinia', broker=config.CELERY_BROKER, backend=config.CELERY_BACKEND)
app.config_from_object(celeryconfig)
# app.autodiscover_tasks()
app.task(task_utils.task_runner, name='task_runner')

if __name__ == '__main__':
  app.start()