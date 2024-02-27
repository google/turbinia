# Copyright 2024 Google Inc.
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

import logging
import traceback

import google.auth
import googleapiclient.discovery

from googleapiclient.errors import HttpError

from turbinia import __version__
from turbinia import TurbiniaException

logger = logging.getLogger('turbinia')


class GCPErrorReporting:
  """This class is used to report errors to Google Cloud."""

  def __init__(self):
    self._credentials, self._project = self._create_credentials()
    try:
      self.logging_client = googleapiclient.discovery.build(
          'clouderrorreporting',
          'v1beta1',
          credentials=self._credentials,
      )
    except google.auth.exceptions.MutualTLSChannelError as exception:
      raise TurbiniaException(
          'Error creating Google API client: {exception}') from exception

  @staticmethod
  def _create_credentials() -> google.auth.credentials.Credentials:
    return google.auth.default()

  def report(self, message, caller=None) -> None:
    if not caller:
      stack = traceback.extract_stack()
      caller = stack[-2]
    file_path = caller[0]
    line_number = caller[1]
    function_name = caller[2]
    report_location = {
        'filePath': file_path,
        'lineNumber': line_number,
        'functionName': function_name
    }

    try:
      self._send_error_report(message, report_location=report_location)
    except HttpError as exception:
      logger.exception('Unable to report error: %s', exception)

  def _send_error_report(self, message, report_location) -> None:
    payload = {
        'serviceContext': {
            'service': 'Turbinia',
            'version': __version__
        },
        'message': f'{message}',
        'context': {
            'reportLocation': report_location
        }
    }

    self.logging_client.projects().events().report(
        projectName=f'projects/{self._project}', body=payload).execute()
