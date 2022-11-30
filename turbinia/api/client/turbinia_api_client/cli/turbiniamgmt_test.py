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
"""Turbinia API client / management tool tests."""

import unittest
import mock

from turbinia_api_client.cli.turbiniamgmt import TurbiniaMgmtCli
from fastapi.testclient import TestClient

from turbinia.api.api_server import app


class TestTurbiniamgmtCli(unittest.TestCase):
  """Turbiniamgmt cli tool tests."""

  # pylint: disable=line-too-long
  _DEFAULT_CONFIG_DICT = {
      'description':
          'This file is used by turbiniamgmt to determine the loccation of the API server and if authentication will be used. These options should match your Turbinia deployment.',
      'comments':
          "By default, the credentials and client secrets files are located in the user's home directory.",
      'API_SERVER_ADDRESS':
          'http://localhost',
      'API_SERVER_PORT':
          8000,
      'API_AUTHENTICATION_ENABLED':
          False,
      'CLIENT_SECRETS_FILENAME':
          '.client_secrets.json',
      'CREDENTIALS_FILENAME':
          '.credentials_default.json'
  }

  def setUp(self) -> None:
    """Sets up the client for the tests."""
    self.api_client = TestClient(app)
    self.client = TurbiniaMgmtCli(config_instance='default', config_path='../')

  def testInitialization(self) -> None:
    """Tests if the client was initialized properly."""
    self.assertIsInstance(self.client, TurbiniaMgmtCli)

  def testReadConfiguration(self) -> None:
    """Tests the client reads the configuration file properly."""
    self.assertEqual(self.client.config_dict, {})
    self.client.read_api_configuration()
    self.assertEqual(self.client.config_dict, self._DEFAULT_CONFIG_DICT)

  @mock.patch(
      'turbinia_api_client.api.turbinia_configuration_api.TurbiniaConfigurationApi.get_evidence_types'
  )
  def testGetEvidenceArguments(self, mock_response) -> None:
    test_response = self.api_client.get('/api/config/evidence')
    mock_response.return_value = test_response
    api_response = self.client.get_evidence_arguments()
    self.assertEqual(test_response, api_response)

  @mock.patch(
      'turbinia_api_client.api.turbinia_configuration_api.TurbiniaConfigurationApi.get_request_options'
  )
  def testGetRequestOptions(self, mock_response) -> None:
    test_response = self.api_client.get('/api/config/request_options')
    mock_response.return_value = test_response
    api_response = self.client.get_request_options()
    self.assertEqual(test_response, api_response)
