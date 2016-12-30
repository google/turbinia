# Copyright 2015 Google Inc.
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
"""Main Turbinia application."""

import logging
import os
import sys

from celery import Celery

from turbinia import config

VERSION = '20150916'

try:
  config.LoadConfig()
except config.TurbiniaConfigException as e:
  # pylint: disable=logging-format-interpolation
  logging.fatal('Could not load Turbinia config: {0:s}'.format(str(e)))
  sys.exit(1)

app = Celery(
    'turbinia',
    broker='redis://{0}:{1}/0'.format(config.REDIS_HOST, config.REDIS_PORT),
    backend='redis://{0}:{1}/0'.format(config.REDIS_HOST, config.REDIS_PORT),
    include=['turbinia.workers.be', 'turbinia.workers.plaso'])

app.conf.CELERY_ROUTES = {
    'turbinia.workers.be.BulkExtractorCalcOffsetsTask': {'queue': 'be-worker'},
    'turbinia.workers.be.BulkExtractorReducerTask': {'queue': 'be-worker'},
    'turbinia.workers.be.BulkExtractorTask': {'queue': 'be-worker'},
    'turbinia.workers.plaso.PlasoTask': {'queue': 'plaso-worker'}
}
app.conf.CELERY_ACCEPT_CONTENT = ['json']
app.conf.CELERY_TASK_SERIALIZER = 'json'
app.conf.CELERY_RESULT_SERIALIZER = 'json'

if __name__ == '__main__':
  app.start()
