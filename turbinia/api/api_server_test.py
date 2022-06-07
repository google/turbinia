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
import json

from fastapi.testclient import TestClient

from turbinia.api.api_server import app
from turbinia import state_manager
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
    config.LoadConfig()
    self.client = TestClient(app)
    self.state_manager = state_manager.get_state_manager()
    self.state_manager.client.set(
        'TurbiniaTask:c8f73a5bc5084086896023c12c7cc026',
        json.dumps(self._TASK_TEST_DATA))

  def tearDown(self):
    """Delete temporary Redis key."""
    self.state_manager.client.delete(
        "TurbiniaTask:{}".format("c8f73a5bc5084086896023c12c7cc026"))

  def testReadRoot(self):
    """Test root route."""
    response = self.client.get("/")
    self.assertEqual(response.status_code, 404)
    self.assertEqual(response.json(), {"detail": "Not Found"})

  def testGetTaskStatus(self):
    """Test getting task status."""
    self.maxDiff = None
    response = self.client.get(
        '/task/{}'.format(self._TASK_TEST_DATA.get('id')))
    self.assertEqual(response.json(), self._TASK_TEST_DATA)

  def testGetRequestStatus(self):
    """Test getting request status."""
    self.maxDiff = None
    response = self.client.get(
        '/request/{}'.format(self._REQUEST_TEST_DATA.get('request_id')))
    self.assertEqual(response.json(), self._REQUEST_TEST_DATA)

  def testGetConfig(self):
    """Test getting current Turbinia server config."""
    config_dict = config.toJSON()
    response = self.client.get('/config')
    self.assertEqual(response.json(), config_dict)

  def testRequestResults(self):
    """Test getting request result files."""
    response = self.client.get(
        '/result/request/{}'.format(self._REQUEST_TEST_DATA.get('request_id')))
    self.assertEqual(response.status_code, 404)
    self.assertEqual(
        response.json(), {'detail': 'Output path could not be found.'})

  def testTaskResults(self):
    """Test getting task result files."""
    response = self.client.get(
        '/result/task/{}'.format(self._TASK_TEST_DATA.get('id')))
    self.assertEqual(response.status_code, 404)
    self.assertEqual(
        response.json(), {'detail': 'Output path could not be found.'})