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

import logging
import os
import json

from google.cloud import logging as cloud_logging
from google.cloud import error_reporting
from google.cloud import exceptions

from turbinia import TurbiniaException


def setup_stackdriver_handler(project_id):
  """Set up Google Cloud Stackdriver Logging

  The Google Cloud Logging library will attach itself as a
  handler to the default Python logging module.

  Attributes:
    project_id: The name of the Google Cloud project.
  Raises:
    TurbiniaException: When an error occurs enabling GCP Stackdriver Logging.
  """
  try:
    client = cloud_logging.Client(project=project_id)
    cloud_handler = cloud_logging.handlers.CloudLoggingHandler(client)
    logger = logging.getLogger('turbinia')
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


def get_logs(project_id, output_dir, query=None):
  """Copies stackdriver logs to a local directory.

  Attributes:
    project_id: The name of the Google Cloud project.
    output_dir: The directory where logs are stored.
    query: Query to use to pull stackdriver logs. 
  Raises:
    TurbiniaException: When an error happens pulling the logs.
  """
  if not query:
    query = 'logName="projects/{}/logs/python"'.format(project_id)
  output_file = open(os.path.join(output_dir,"turbinia_stackdriver_logs.jsonl"), "w")
  try:
    client = cloud_logging.Client(project=project_id)
    for entry in client.list_entries(
        order_by=cloud_logging.DESCENDING, filter_=query):
      output_file.write(json.dumps(entry.to_api_repr()))
      output_file.write('\n')
    output_file.close()
  except exceptions.GoogleCloudError as exception:
    output_file.close()
    msg = 'Error enabling Stackdriver Logging: {0:s}'.format(str(exception))
    raise TurbiniaException(msg)      

