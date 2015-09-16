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

import os

from celery import Celery

VERSION = '20150916'
REDIS_HOST = os.environ['REDIS_SVC_PORT_6379_TCP_ADDR']
REDIS_PORT = os.environ['REDIS_SVC_PORT_6379_TCP_PORT']

app = Celery(
    'turbinia',
    broker='redis://{0}:{1}/0'.format(REDIS_HOST, REDIS_PORT),
    backend='redis://{0}:{1}/0'.format(REDIS_HOST, REDIS_PORT),
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
