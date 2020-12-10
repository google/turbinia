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

from google.cloud import logging as cloud_logging
from google.cloud import error_reporting
from google.cloud import exceptions

from turbinia import TurbiniaException

import datetime

class CustomFormatter(logging.Formatter):
  def __init__(self, environment,  *args, **kwargs):
    super(CustomFormatter, self).__init__(*args, **kwargs)
    self.environment = environment
  def format(self, record):
    
    logmsg = super(CustomFormatter, self).format(record)

    return {'msg':logmsg, 'other':self.environment}

def setup_stackdriver_handler(project_id, environment):
  """Set up Google Cloud Stackdriver Logging

  The Google Cloud Logging library will attach itself as a
  handler to the default Python logging module.

  Attributes:
    project_id: The name of the Google Cloud project.
    environment: Where the log is running.
  Raises:
    TurbiniaException: When an error occurs enabling GCP Stackdriver Logging.
  """
  try:
    client = cloud_logging.Client(project=project_id)
    cloud_handler = cloud_logging.handlers.CloudLoggingHandler(client)
    cloud_handler.setFormatter(CustomFormatter(environment))
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
