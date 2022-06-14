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
"""Turbinia API server unit tests."""

import unittest
import mock

from fastapi.testclient import TestClient

from turbinia.api.api_server import app
from turbinia import config


class testTurbiniaAPIServer(unittest.TestCase):
  """ Test Turbinia API server."""

  _TASK_TEST_DATA = {
      'id': 'c8f73a5bc5084086896023c12c7cc026',
      'job_id': '1db0dc47d8f244f5b4fa7e15b8a87861',
      'last_update': '2022-04-01T19:17:14.791074Z',
      'name': 'CronAnalysisTask',
      'request_id': '41483253079448e59685d88f37ab91f7',
      'requester': 'root',
      'group_id': '1234',
      'worker_name': '95153920ab11',
      'report_data': 'No issues found in crontabs',
      'report_priority': 80,
      'run_time': 46.003234,
      'status': 'No issues found in crontabs',
      'saved_paths': '/tmp/worker-log.txt',
      'successful': True,
      'instance': 'turbinia-jleaniz-test'
  }

  _REQUEST_TEST_DATA = {
      'request_id': '41483253079448e59685d88f37ab91f7',
      'reason': None,
      'tasks': [_TASK_TEST_DATA,],
      'requester': 'root',
      'last_task_update_time': '2022-04-01T19:17:14.791074Z',
      'status': 'successful',
      'task_count': 1,
      'successful_tasks': 1,
      'running_tasks': 0,
      'failed_tasks': 0
  }

  def setUp(self):
    """This method will write a temporary key to redis for testing purposes."""
    self.client = TestClient(app)

  @mock.patch('fastapi.testclient.TestClient')
  def testReadRoot(self, testClient):
    """Test root route."""
    testClient.get = mock.MagicMock()
    testClient.get.return_value = {"detail": "Not Found"}
    response = testClient.get("/")
    self.assertEqual(response, {"detail": "Not Found"})

  @mock.patch('fastapi.testclient.TestClient')
  def testGetTaskStatus(self, testClient):
    """Test getting task status."""
    self.maxDiff = None
    testClient.get = mock.MagicMock()
    testClient.get.return_value = self._TASK_TEST_DATA
    response = testClient.get('/task/{}'.format(self._TASK_TEST_DATA.get('id')))
    self.assertEqual(response, self._TASK_TEST_DATA)

  @mock.patch('fastapi.testclient.TestClient')
  def testGetRequestStatus(self, testClient):
    """Test getting request status."""
    self.maxDiff = None
    testClient.get = mock.MagicMock()
    testClient.get.return_value = self._REQUEST_TEST_DATA
    response = testClient.get(
        '/request/{}'.format(self._REQUEST_TEST_DATA.get('request_id')))
    self.assertEqual(response, self._REQUEST_TEST_DATA)

  @mock.patch('fastapi.testclient.TestClient')
  def testGetConfig(self, testClient):
    """Test getting current Turbinia server config."""
    config_dict = config.toJSON()
    testClient.get = mock.MagicMock()
    testClient.get.return_value = config_dict
    response = testClient.get('/config')
    self.assertEqual(response, config_dict)

  @mock.patch('fastapi.testclient.TestClient')
  def testRequestResults(self, testClient):
    """Test getting request result files."""
    testClient.get = mock.MagicMock()
    testClient.get.return_value = {'detail': 'Output path could not be found.'}
    response = testClient.get(
        '/result/request/{}'.format(self._REQUEST_TEST_DATA.get('request_id')))
    self.assertEqual(response, {'detail': 'Output path could not be found.'})

  @mock.patch('fastapi.testclient.TestClient')
  def testTaskResults(self, testClient):
    """Test getting task result files."""
    testClient.get = mock.MagicMock()
    testClient.get.return_value = {'detail': 'Task ID not found'}
    response = testClient.get(
        '/result/task/{}'.format(self._TASK_TEST_DATA.get('id')))
    self.assertEqual(response, {'detail': 'Task ID not found'})

  # TODO: add tests to check for task count accuracy