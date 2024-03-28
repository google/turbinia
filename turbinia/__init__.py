# -*- coding: utf-8 -*-
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

from importlib import metadata as importlib_metadata

log = logging.getLogger(__name__)

try:
  dist = importlib_metadata.distribution(__name__)
  __version__ = dist.version
except importlib_metadata.PackageNotFoundError:
  __version__ = 'unknown'


def log_and_report(message, trace):
  """Log an error and if enabled, send to GCP Error Reporting API.

  Args:
    message(str): The user defined message to log.
    trace(str): The error traceback message to log.
  """
  from turbinia import config

  log.error(message)
  log.error(trace)
  # If GCP Error Reporting is enabled.
  config.LoadConfig()
  if config.CLOUD_PROVIDER.lower() == 'gcp' and config.STACKDRIVER_TRACEBACK:
    # Only load google_cloud if needed
    from turbinia.lib import google_cloud
    error_client = google_cloud.GCPErrorReporting()
    message = f'{message}:{trace}'
    error_client.report(message)


class TurbiniaException(Exception):
  """Turbinia Exception class."""
  pass
