# -*- coding: utf-8 -*-
# Copyright 2022 Google Inc.
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
"""Turbinia API client command-line tool."""

import unittest
import mock
import pathlib

from turbinia_client.turbiniacli import TurbiniaCli
from fastapi.testclient import TestClient

from turbinia.api.api_server import app


class TestTurbiniaCli(unittest.TestCase):
  """Turbinia-client cli tool tests."""

  def setUp(self) -> None:
    """Sets up the client for the tests."""
    self.api_client = TestClient(app)
    config_path = pathlib.Path(__file__).parent.parent
    self.client = TurbiniaCli(
        config_instance='default', config_path=config_path)

  def testInitialization(self) -> None:
    """Tests if the client was initialized properly."""
    self.assertIsInstance(self.client, TurbiniaCli)

  def testReadConfiguration(self) -> None:
    """Tests the client reads the configuration file properly."""
    self.assertEqual(self.client.config_dict, {})
    self.client.read_api_configuration()
    self.assertIn('API_SERVER_ADDRESS', self.client.config_dict)
    self.assertIn('API_SERVER_PORT', self.client.config_dict)
    self.assertIn('API_AUTHENTICATION_ENABLED', self.client.config_dict)
    self.assertIn('CLIENT_SECRETS_FILENAME', self.client.config_dict)
    self.assertIn('CREDENTIALS_FILENAME', self.client.config_dict)

  @mock.patch(
      'turbinia_api_lib.api.turbinia_evidence_api.TurbiniaEvidenceApi.get_evidence_types_with_http_info'
  )
  def testGetEvidenceArguments(self, mock_response) -> None:
    """Tests the get_evidence_arguments method."""
    test_response = self.api_client.get('/api/evidence/types')
    mock_response.return_value = test_response
    api_response = self.client.get_evidence_arguments()
    self.assertEqual(test_response, api_response)

  @mock.patch(
      'turbinia_api_lib.api.turbinia_configuration_api.TurbiniaConfigurationApi.get_request_options_with_http_info'
  )
  def testGetRequestOptions(self, mock_response) -> None:
    """Tests the get_request_options method."""
    test_response = self.api_client.get('/api/config/request_options')
    mock_response.return_value = test_response
    api_response = self.client.get_request_options()
    self.assertEqual(test_response, api_response)
