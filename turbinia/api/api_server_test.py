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

import importlib

from collections import OrderedDict

import unittest
import json
import os
import fakeredis
import mock

from fastapi.testclient import TestClient

from turbinia.api.api_server import app
from turbinia.api.routes.router import api_router
from turbinia.api.routes.ui import ui_router

from turbinia import config as turbinia_config
from turbinia import state_manager
from turbinia.jobs import manager as jobs_manager
from turbinia.workers import TurbiniaTask


class testTurbiniaAPIServer(unittest.TestCase):
  """ Test Turbinia API server."""

  _TASK_TEST_DATA = {
      'id': 'c8f73a5bc5084086896023c12c7cc026',
      'job_id': '1db0dc47d8f244f5b4fa7e15b8a87861',
      'start_time': '2022-04-01T19:15:14.791074Z',
      'last_update': '2022-04-01T19:17:14.791074Z',
      'name': 'YaraAnalysisTask',
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
      'output_manager': '',
      'instance': 'turbinia-jleaniz-test'
  }

  _REQUEST_TEST_DATA = {
      'failed_tasks': 0,
      'last_task_update_time': '2022-04-01T19:17:14.791074Z',
      'queued_tasks': 0,
      'reason': None,
      'request_id': '41483253079448e59685d88f37ab91f7',
      'requester': 'root',
      'running_tasks': 0,
      'status': 'successful',
      'successful_tasks': 1,
      'task_count': 1,
      'tasks': []
  }

  def _get_state_manager(self):
    """Gets a Redis State Manager object for test."""
    turbinia_config.STATE_MANAGER = 'Redis'
    # force state_manager module to reload using Redis state manager.
    importlib.reload(state_manager)
    return state_manager.get_state_manager()

  def setUp(self):
    """This method will write a temporary key to redis for testing purposes."""
    self.client = TestClient(app)
    self.state_manager = self._get_state_manager()

  def testWebRoutes(self):
    """Test Web UI routes."""
    ui_routes = ui_router.routes
    for route in ui_routes:
      self.assertIn(route, self.client.app.routes)

  def testAPIroutes(self):
    """Test API server routes."""
    api_routes = api_router.routes
    for route in api_routes:
      self.assertIn(route, self.client.app.routes)

  def testGetConfig(self):
    """Test getting current Turbinia server config."""
    config_dict = turbinia_config.toDict()
    response = self.client.get('/api/config')
    self.assertEqual(response.json(), config_dict)

  def testRequestResultsNotFound(self):
    """Test getting empty request result files."""
    request_id = self._REQUEST_TEST_DATA.get('request_id')
    response = self.client.get('/api/result/request/{}'.format(request_id))
    log_path = turbinia_config.toDict().get('OUTPUT_DIR')
    output_path = os.path.join(log_path, request_id)
    self.assertEqual(response.status_code, 404)
    self.assertEqual(
        response.json(), {
            'detail':
                'Output path {0:s} for request {1:s} could not be found.'
                .format(output_path, request_id)
        })

  @mock.patch('turbinia.state_manager.RedisStateManager.get_task_data')
  def testTaskResultsNotFound(self, testTaskData):
    """Test getting empty task result files."""
    testTaskData.return_value = []
    task_id = self._TASK_TEST_DATA.get('id')
    response = self.client.get('/api/result/task/{}'.format(task_id))
    self.assertEqual(response.status_code, 404)
    self.assertEqual(
        response.json(), {'detail': 'Task {0:s} not found.'.format(task_id)})

  @mock.patch('turbinia.state_manager.RedisStateManager.get_task_data')
  def testGetTaskStatus(self, testTaskData):
    """Test getting task status."""
    redis_client = fakeredis.FakeStrictRedis()
    input_task = TurbiniaTask().deserialize(self._TASK_TEST_DATA)
    expected_result_dict = OrderedDict(sorted(input_task.serialize().items()))
    expected_result_str = json.dumps(expected_result_dict)

    redis_client.set(
        'TurbiniaTask:41483253079448e59685d88f37ab91f7', expected_result_str)

    testTaskData.return_value = [
        json.loads(
            redis_client.get('TurbiniaTask:41483253079448e59685d88f37ab91f7'))
    ]

    result = self.client.get(
        '/api/task/{}'.format(self._TASK_TEST_DATA.get('id')))
    result = json.loads(result.content)
    self.assertEqual(expected_result_dict, result)

  @mock.patch('turbinia.state_manager.RedisStateManager.get_task_data')
  def testRequestStatus(self, testTaskData):
    """Test getting Turbinia Request status."""
    redis_client = fakeredis.FakeStrictRedis()
    input_task = TurbiniaTask().deserialize(self._TASK_TEST_DATA)
    input_task_serialized = input_task.serialize()
    expected_result = self._REQUEST_TEST_DATA.copy()
    expected_result['tasks'] = [input_task_serialized]
    expected_result_dict = OrderedDict(sorted(expected_result.items()))

    redis_client.set(
        'TurbiniaTask:41483253079448e59685d88f37ab91f7',
        json.dumps(input_task_serialized))
    testTaskData.return_value = [
        json.loads(
            redis_client.get('TurbiniaTask:41483253079448e59685d88f37ab91f7'))
    ]

    result = self.client.get(
        '/api/request/{}'.format(self._REQUEST_TEST_DATA.get('request_id')))
    result = json.loads(result.content)
    self.assertEqual(expected_result_dict, result)

  @mock.patch('turbinia.state_manager.RedisStateManager.get_task_data')
  def testRequestSummary(self, testTaskData):
    """Test getting Turbinia Request status summary."""
    redis_client = fakeredis.FakeStrictRedis()
    input_task = TurbiniaTask().deserialize(self._TASK_TEST_DATA)
    input_task_serialized = input_task.serialize()
    expected_result = {'requests_status': [self._REQUEST_TEST_DATA]}

    redis_client.set(
        'TurbiniaTask:41483253079448e59685d88f37ab91f7',
        json.dumps(input_task_serialized))

    testTaskData.return_value = [
        json.loads(
            redis_client.get('TurbiniaTask:41483253079448e59685d88f37ab91f7'))
    ]

    result = self.client.get('/api/request/summary')
    result = json.loads(result.content)
    self.assertEqual(expected_result, result)

  @mock.patch('turbinia.state_manager.RedisStateManager.get_task_data')
  def testRequestNotFound(self, testTaskData):
    """Test getting invalid Turbinia Request status."""
    expected_result = {
        'detail': 'Request ID not found or the request had no associated tasks.'
    }
    testTaskData.return_value = []
    result = self.client.get(
        '/api/request/{}'.format(self._REQUEST_TEST_DATA.get('request_id')))
    result = json.loads(result.content)
    self.assertEqual(expected_result, result)

  @mock.patch('turbinia.state_manager.RedisStateManager.get_task_data')
  def testTaskNotFound(self, testTaskData):
    """Test getting invalid Turbinia task status."""
    expected_result = {'detail': 'Task ID not found.'}
    testTaskData.return_value = []
    result = self.client.get(
        '/api/task/{}'.format(self._TASK_TEST_DATA.get('id')))
    result = json.loads(result.content)
    self.assertEqual(expected_result, result)

  def testGetJobs(self):
    """Test getting Turbinia job names."""
    _jobs_manager = jobs_manager.JobsManager()
    registered_jobs = set(_jobs_manager.GetJobNames())
    disabled_jobs = set(turbinia_config.CONFIG.DISABLED_JOBS)
    expected_result = list(registered_jobs.difference(disabled_jobs))

    result = self.client.get('/api/jobs')
    result = json.loads(result.content)
    self.assertEqual(expected_result, result)
