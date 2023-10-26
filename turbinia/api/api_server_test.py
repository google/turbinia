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

import datetime
import unittest
import json
import os
import fakeredis
import mock

from fastapi.testclient import TestClient

from turbinia.api.api_server import app
from turbinia.api.routes.router import api_router
from turbinia.api.routes.ui import ui_router
from turbinia.api.cli.turbinia_client.helpers import formatter

from turbinia import config as turbinia_config
from turbinia import state_manager
from turbinia.jobs import manager as jobs_manager
from turbinia.workers import TurbiniaTask

from textwrap import dedent


class testTurbiniaAPIServer(unittest.TestCase):
  """ Test Turbinia API server."""

  _TASK_TEST_DATA = {
      'id': 'c8f73a5bc5084086896023c12c7cc026',
      'evidence_name': '/evidence/test.tgz',
      'evidence_id': '084d5904f3d2412b99dc29ed34853a16',
      'all_args': 'compresseddirectory -l /evidence/test.tgz',
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
      'evidence_name': '/evidence/test.tgz',
      'evidence_id': '084d5904f3d2412b99dc29ed34853a16',
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

  _EVIDENCE_TEST_DATA = {
      'request_id': '5581344e306b42ccb965a19028d4fc58',
      'tasks': [
          'b73d484634164e0eb1870d101ca9ce2f',
          'dd810119ac2443e18b69ea56c10c0a9b', 'ac4dc14080b144478437818a694e2f4d'
      ],
      'copyable': False,
      'cloud_only': False,
      'local_path': '/workspaces/turbinia/test_data/artifact_disk.dd',
      'source_path': '/workspaces/turbinia/test_data/artifact_disk.dd',
      'resource_tracked': False,
      'processed_by': [],
      'resource_id': None,
      'credentials': [],
      'config': {
          'globals': {
              'debug_tasks': False,
              'jobs_allowlist': [],
              'jobs_denylist': [],
              'yara_rules': '',
              'filter_patterns': [],
              'sketch_id': None,
              'group_name': '',
              'reason': '',
              'all_args': 'turbinia/turbiniactl.py rawdisk -l disk.dd',
              'group_id': '55ce6e98dc154e73990b24f0c79ab07e',
              'requester': 'root'
          }
      },
      'tags': {},
      'creation_time': '2023-08-04T19:16:28.182774Z',
      'last_update': '2023-08-04T19:17:58.769212Z',
      'parent_evidence': None,
      'size': 20971520,
      'mount_path': None,
      'device_path': None,
      'has_child_evidence': False,
      'save_metadata': False,
      'type': 'RawDisk',
      '_name': '/workspaces/turbinia/test_data/artifact_disk.dd',
      'context_dependent': False,
      'state': {},
      'id': 'b510ab6bf11a410da1fd9d9b128e7d74',
      'hash': '4cf679344af02c2b89e4a902f939f4608bcac0fbf81511da13d7d9b9',
      'description': None
  }

  _SORTED_KEYS_SUMMARY = {
      '5581344e306b42ccb965a19028d4fc58': [
          'TurbiniaEvidence:b510ab6bf11a410da1fd9d9b128e7d74'
      ],
      '6d6f85f44487441c9d4da1bda56ae90a': [
          'TurbiniaEvidence:e2d9bff0c78b471e820db55080012f44',
          'TurbiniaEvidence:0114968b6293410e818eb1ec72db56f8'
      ]
  }

  _COUNT_SUMMARY = 3

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
    response = self.client.get(f'/api/result/request/{request_id}')
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
    response = self.client.get(f'/api/result/task/{task_id}')
    self.assertEqual(response.status_code, 404)
    self.assertEqual(
        response.json(), {'detail': f'Task {task_id:s} not found.'})

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

    result = self.client.get(f"/api/task/{self._TASK_TEST_DATA.get('id')}")
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
        f"/api/request/{self._REQUEST_TEST_DATA.get('request_id')}")
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
  def testRequestEvidenceNoArgs(self, testTaskData):
    """Test getting Turbinia Request evidence name without all_args."""
    redis_client = fakeredis.FakeStrictRedis()
    input_task = TurbiniaTask().deserialize(self._TASK_TEST_DATA)
    input_task_serialized = input_task.serialize()
    input_task_serialized.pop('all_args')
    expected_result = self._REQUEST_TEST_DATA['evidence_name']

    redis_client.set(
        'TurbiniaTask:41483253079448e59685d88f37ab91f7',
        json.dumps(input_task_serialized))

    testTaskData.return_value = [
        json.loads(
            redis_client.get('TurbiniaTask:41483253079448e59685d88f37ab91f7'))
    ]

    result = self.client.get('/api/request/summary')
    result = json.loads(result.content)
    evidence_name = result['requests_status'][0]['evidence_name']

    self.assertEqual(expected_result, evidence_name)

  @mock.patch('turbinia.state_manager.RedisStateManager.get_task_data')
  def testRequestNotFound(self, testTaskData):
    """Test getting invalid Turbinia Request status."""
    expected_result = {
        'detail': 'Request ID not found or the request had no associated tasks.'
    }
    testTaskData.return_value = []
    result = self.client.get(
        f"/api/request/{self._REQUEST_TEST_DATA.get('request_id')}")
    result = json.loads(result.content)
    self.assertEqual(expected_result, result)

  @mock.patch('turbinia.state_manager.RedisStateManager.get_task_data')
  def testTaskNotFound(self, testTaskData):
    """Test getting invalid Turbinia task status."""
    expected_result = {'detail': 'Task ID not found.'}
    testTaskData.return_value = []
    result = self.client.get(f"/api/task/{self._TASK_TEST_DATA.get('id')}")
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

  @mock.patch('turbinia.api.routes.evidence.redis_manager.get_evidence_data')
  def testGetEvidence(self, testGetEvidence):
    """Test getting Turbinia evidence."""
    testGetEvidence.return_value = self._EVIDENCE_TEST_DATA
    response = self.client.get(
        f'/api/evidence/{self._EVIDENCE_TEST_DATA["id"]}')
    result = json.loads(response.content)
    self.assertEqual(self._EVIDENCE_TEST_DATA, result)

  @mock.patch('turbinia.api.routes.evidence.redis_manager.get_evidence_data')
  def testGetEvidenceNotFound(self, testGetEvidence):
    """Test getting non-existent evidence."""
    testGetEvidence.return_value = {}
    evidence_id = '4774873a11f049233e863a009b997'
    response = self.client.get(f'/api/evidence/{evidence_id}')
    self.assertEqual(response.status_code, 404)
    self.assertEqual(
        response.json(), {
            'detail':
                f'UUID {evidence_id} not found or it had no associated '
                f'evidences.'
        })

  @mock.patch('turbinia.api.routes.evidence.redis_manager.get_evidence_summary')
  def testEvidenceSummary(self, testGetEvidenceSummary):
    """Test getting evidence summary."""
    testGetEvidenceSummary.return_value = self._SORTED_KEYS_SUMMARY
    response = self.client.get(
        '/api/evidence/summary?output=keys, group=request_id')
    grouped_keys_result = json.loads(response.content)
    testGetEvidenceSummary.return_value = self._COUNT_SUMMARY
    response = self.client.get('/api/evidence/summary?output=count')
    count_result = json.loads(response.content)
    self.assertEqual(self._SORTED_KEYS_SUMMARY, grouped_keys_result)
    self.assertEqual(self._COUNT_SUMMARY, count_result)

  def testEvidenceSummaryWrongAttribute(self):
    """Test getting evidence summary grouped with invalid attribute."""
    attribute = 'test_attribute'
    response = self.client.get(f'api/evidence/summary?group={attribute}')
    self.assertEqual(response.status_code, 400)
    self.assertEqual(
        response.json()['detail'].split('.')[0],
        f'Cannot group by attribute {attribute}')

  @mock.patch('turbinia.api.routes.evidence.redis_manager.get_evidence_summary')
  def testEvidenceSummaryNotFound(self, testGetEvidenceSummary):
    """Test getting evidence summary with no evidence in the server."""
    testGetEvidenceSummary.return_value = {}
    response = self.client.get(f'/api/evidence/summary')
    self.assertEqual(response.status_code, 404)
    self.assertEqual(response.json(), {'detail': f'No evidence found.'})

  @mock.patch('turbinia.api.routes.evidence.redis_manager.query_evidence')
  def testEvidenceQuery(self, testQueryEvidence):
    """Test querying evidence."""
    request_id = '6d6f85f44487441c9d4da1bda56ae90a'
    testQueryEvidence.return_value = self._SORTED_KEYS_SUMMARY[request_id]
    response = self.client.get(
        f'/api/evidence/query?attribute_name=request_id'
        f'&attribute_value={request_id}&output=keys')
    result = json.loads(response.content)
    self.assertEqual(self._SORTED_KEYS_SUMMARY[request_id], result)

  def testEvidenceQueryWrongAttribute(self):
    """Test querying evidence with invalid attribute."""
    attribute = 'test_attribute'
    response = self.client.get(
        f'api/evidence/query?attribute_name={attribute}&attribute_value="test"')
    self.assertEqual(response.status_code, 400)
    self.assertEqual(
        response.json()['detail'].split('.')[0], f'Cannot query by {attribute}')

  @mock.patch('turbinia.api.routes.evidence.redis_manager.query_evidence')
  def testEvidenceQueryNotFound(self, testQueryEvidence):
    """Test querying evidence with no evidence in the server."""
    request_id = '6d6f85f44487441c9d4da1bda56ae90a'
    testQueryEvidence.return_value = {}
    response = self.client.get(
        f'/api/evidence/query?attribute_name=request_id'
        f'&attribute_value={request_id}')
    self.assertEqual(response.status_code, 404)
    self.assertEqual(
        response.json(), {
            'detail': (
                f'No evidence found with value {request_id} in attribute '
                f'request_id.')
        })

  @mock.patch('turbinia.state_manager.RedisStateManager.get_attribute')
  @mock.patch('turbinia.api.routes.evidence.datetime')
  @mock.patch('turbinia.api.routes.evidence.os.makedirs')
  def testEvidenceUpload(
      self, mock_makedirs, mock_datetime, mock_get_attribute):
    """Tests uploading evidence."""
    mocked_now = datetime.datetime.now()
    mock_datetime.now.return_value = mocked_now
    mocked_now_str = mocked_now.strftime(turbinia_config.DATETIME_FORMAT)

    filedir = os.path.dirname(os.path.realpath(__file__))
    evidence_1_name = 'wordpress_access_logs.txt'
    evidence_2_name = 'mbr.raw'
    evidence_1_path = os.path.join(
        filedir, '..', '..', 'test_data', evidence_1_name)
    evidence_2_path = os.path.join(
        filedir, '..', '..', 'test_data', evidence_2_name)
    ticket_id = '981234098'

    expected_evidence_1_name = (
        f'{os.path.splitext(evidence_1_name)[0]}_{mocked_now_str}')
    expected_evidence_2_name = (
        f'{os.path.splitext(evidence_2_name)[0]}_{mocked_now_str}')
    expected_evidence_1_path = os.path.join(
        turbinia_config.API_EVIDENCE_UPLOAD_DIR, ticket_id,
        expected_evidence_1_name)
    expected_evidence_2_path = os.path.join(
        turbinia_config.API_EVIDENCE_UPLOAD_DIR, ticket_id,
        expected_evidence_2_name)
    expected_response = [{
        'original_name': evidence_1_name,
        'file_name': expected_evidence_1_name,
        'file_path': expected_evidence_1_path,
        'size': 2265,
        'hash': '2bc7c964403ea416bf2cf9871f2385dcccdc625c46fa8d12a3f54b86'
    }, {
        'original_name': evidence_2_name,
        'file_name': expected_evidence_2_name,
        'file_path': expected_evidence_2_path,
        'size': 4194304,
        'hash': 'b5cfa74c1c6e1ba459c7ef68fc1bf3725d2c0a9bb63923350a13ea76'
    }]

    files = [('files', open(evidence_1_path, 'rb')),
             ('files', open(evidence_2_path, 'rb'))]
    with mock.patch('turbinia.api.routes.evidence.open',
                    mock.mock_open()) as mocked_file:
      response = self.client.post(
          '/api/evidence/upload', files=files, data={
              'ticket_id': ticket_id,
              'calculate_hash': True
          })
      mocked_file.assert_called()
      mocked_file.assert_called_with(expected_evidence_2_path, 'wb')
    self.assertEqual(response.status_code, 200)
    self.assertEqual(json.loads(response.content), expected_response)
