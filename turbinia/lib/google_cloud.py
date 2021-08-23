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
"""Google Cloud resources library."""

from __future__ import unicode_literals

import datetime
from datetime import timedelta
from turbinia.config import DATETIME_FORMAT
import logging
import os
import json

from google.cloud import logging as cloud_logging
from google.cloud import error_reporting
from google.cloud import exceptions
from google.api_core import exceptions as google_api_exceptions
from googleapiclient.errors import HttpError

from turbinia import TurbiniaException
from google.cloud.logging_v2 import _helpers
from google.cloud.logging_v2.handlers.transports.background_thread import _Worker

logger = logging.getLogger('turbinia')


def setup_stackdriver_handler(project_id, origin):
  """Set up Google Cloud Stackdriver Logging

  The Google Cloud Logging library will attach itself as a
  handler to the default Python logging module.

  Attributes:
    project_id: The name of the Google Cloud project.
    origin: Where the log is originating from.(i.e. server, worker)
  Raises:
    TurbiniaException: When an error occurs enabling GCP Stackdriver Logging.
  """

  # Patching cloud logging to allow custom fields
  def my_enqueue(self, record, message, **kwargs):
    queue_entry = {
        "info": {
            "message": message,
            "python_logger": record.name,
            "origin": origin
        },
        "severity": _helpers._normalize_severity(record.levelno),
        "timestamp": datetime.datetime.utcfromtimestamp(record.created),
    }

    queue_entry.update(kwargs)
    self._queue.put_nowait(queue_entry)

  _Worker.enqueue = my_enqueue

  try:
    client = cloud_logging.Client(project=project_id)
    cloud_handler = cloud_logging.handlers.CloudLoggingHandler(client)
    logger.addHandler(cloud_handler)

  except exceptions.GoogleCloudError as exception:
    msg = 'Error enabling Stackdriver Logging: {0:s}'.format(str(exception))
    raise TurbiniaException(msg)


def setup_stackdriver_traceback(project_id):
  """Set up Google Cloud Error Reporting

  This method will enable Google Cloud Error Reporting.
  All exceptions that occur within a Turbinia Task will be logged.

  Attributes:
    project_id: The name of the Google Cloud project.
  Raises:
    TurbiniaException: When an error occurs enabling GCP Error Reporting.
  """
  try:
    client = error_reporting.Client(project=project_id)
  except exceptions.GoogleCloudError as exception:
    msg = 'Error enabling GCP Error Reporting: {0:s}'.format(str(exception))
    raise TurbiniaException(msg)
  return client


def get_logs(project_id, output_dir=None, days=1, query=None):
  """Copies stackdriver logs to a local directory.

  Attributes:
    project_id: The name of the Google Cloud project.
    output_dir: The directory where logs are stored.
    query: Query to use to pull stackdriver logs. 
    days: number of days we want history for.
  Raises:
    TurbiniaException: When an error happens pulling the logs.
  """
  if not query:
    query = 'jsonPayload.python_logger="turbinia"'
  start_time = datetime.datetime.now() - timedelta(days=days)
  start_string = start_time.strftime(DATETIME_FORMAT)
  complete_query = '{0:s} timestamp>="{1:s}"'.format(query, start_string)
  if output_dir:
    file_path = os.path.join(
        output_dir, 'turbinia_stackdriver_logs_{0:s}.jsonl'.format(
            datetime.datetime.now().strftime('%s')))
    output_file = open(file_path, 'w')
    logger.info('Writing the logs to {0:s}'.format(file_path))
  try:
    client = cloud_logging.Client(project=project_id)
    logger.info(
        'Collecting the stackdriver logs with the following query: {0:s}'
        .format(complete_query))

    for entry in client.list_entries(order_by=cloud_logging.DESCENDING,
                                     filter_=complete_query):
      if not output_dir:
        logger.info(json.dumps(entry.to_api_repr()))
      else:
        output_file.write(json.dumps(entry.to_api_repr()))
        output_file.write('\n')
    if output_dir:
      output_file.close()
  except google_api_exceptions.InvalidArgument as exception:
    msg = 'Unable to parse query {0!s} with error {1!s}'.format(
        query, exception)
    raise TurbiniaException(msg)
  except HttpError as exception:
    msg = 'HTTP error querying logs. Make sure you have the right access on the project.{0!s}'.format(
        exception)
    raise TurbiniaException(msg)
  except google_api_exceptions.GoogleAPIError as exception:
    msg = 'Something went wrong with the API. {0!s}'.format(exception)
    raise TurbiniaException(msg)
