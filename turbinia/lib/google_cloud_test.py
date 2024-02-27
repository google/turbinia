# -*- coding: utf-8 -*-
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

import mock
import unittest

from turbinia.lib import google_cloud


class GoogleCLoudErrorReportingTest(unittest.TestCase):
  """Tests for GCP Error reporting functions."""

  @mock.patch('google.auth.default')
  @mock.patch('googleapiclient.discovery.build')
  @mock.patch('turbinia.lib.google_cloud.GCPErrorReporting._send_error_report')
  def testStackDriverSetup(self, mock_send, mock_build, mock_credentials):
    """Test object instantiation."""
    mock_credentials.return_value = ('fake-project-id', 'fake-credentials')
    client_test = google_cloud.GCPErrorReporting()
    self.assertIsInstance(client_test, google_cloud.GCPErrorReporting)
