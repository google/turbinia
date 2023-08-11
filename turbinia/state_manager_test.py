# -*- coding: utf-8 -*-
# Copyright 2016 Google Inc.
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
"""Tests the state manager module."""

from __future__ import unicode_literals

import copy
import json
import os
import tempfile
import unittest
from unittest import mock

from turbinia import config
from turbinia.workers import TurbiniaTask
from turbinia.workers import TurbiniaTaskResult

from turbinia import state_manager


class TestPSQStateManager(unittest.TestCase):
  """Test PSQStateManager class."""

  def _get_state_manager(self):
    """Gets a Datastore State Manager object for test."""
    config.STATE_MANAGER = 'Datastore'
    return state_manager.get_state_manager()

  @mock.patch('turbinia.state_manager.redis.Client')
  def setUp(self, _):
    self.remove_files = []
    self.remove_dirs = []
    self.state_manager = None

    config.LoadConfig()
    self.state_manager_save = config.STATE_MANAGER

    self.test_data = {
        'name': 'TestTask',
        'request_id': 'TestRequestId',
        'group_id': 'TestGroupId',
        'status': 'TestStatus',
        'saved_paths': ['testpath1', 'testpath2']
    }

    # Set up TurbiniaTask
    self.base_output_dir = tempfile.mkdtemp()
    self.task = TurbiniaTask(
        base_output_dir=self.base_output_dir, name=self.test_data['name'],
        request_id=self.test_data['request_id'],
        group_id=self.test_data['group_id'])
    self.task.output_manager = mock.MagicMock()
    self.task.output_manager.get_local_output_dirs.return_value = (
        '/fake/tmp/dir', self.base_output_dir)

    # Set up TurbiniaTaskResult
    self.result = TurbiniaTaskResult(base_output_dir=self.base_output_dir)
    self.result.setup(self.task)
    self.result.status = self.test_data['status']
    self.result.saved_paths = self.test_data['saved_paths']
    self.task.result = self.result

  def tearDown(self):
    config.STATE_MANAGER = self.state_manager_save
    [os.remove(f) for f in self.remove_files if os.path.exists(f)]
    [os.rmdir(d) for d in self.remove_dirs if os.path.exists(d)]
    os.rmdir(self.base_output_dir)

  @mock.patch('turbinia.state_manager.datastore.Client')
  def testStateManagerGetTaskDict(self, _):
    """Test State Manager get_task_dict()."""
    self.state_manager = self._get_state_manager()

    task_dict = self.state_manager.get_task_dict(self.task)

    # Make the returned task_dict contains all of our test data
    self.assertEqual(task_dict['name'], self.test_data['name'])
    self.assertEqual(task_dict['request_id'], self.test_data['request_id'])
    self.assertEqual(task_dict['status'], self.test_data['status'])
    self.assertEqual(len(task_dict['saved_paths']), 2)
    self.assertEqual(task_dict['group_id'], self.test_data['group_id'])
    self.assertTrue('instance' in task_dict)
    self.assertIn(self.test_data['saved_paths'][0], task_dict['saved_paths'])

  @mock.patch('turbinia.state_manager.datastore.Client')
  def testStateManagerValidateDataValidDict(self, _):
    """Test State Manager _validate_data() base case."""
    self.state_manager = self._get_state_manager()
    # pylint: disable=protected-access
    test_data = self.state_manager._validate_data(self.test_data)
    self.assertDictEqual(test_data, self.test_data)

  @mock.patch('turbinia.state_manager.datastore.Client')
  def testStateManagerValidateDataInvalidDict(self, _):
    """Test State Manager _validate_data() with invalid large input."""
    self.state_manager = self._get_state_manager()
    invalid_dict = copy.deepcopy(self.test_data)
    invalid_dict['status'] = 'A' * state_manager.MAX_DATASTORE_STRLEN + 'BORKEN'
    # pylint: disable=protected-access
    test_data = self.state_manager._validate_data(invalid_dict)
    self.assertListEqual(list(test_data.keys()), list(self.test_data.keys()))
    self.assertNotEqual(test_data['status'], self.test_data['status'])
    self.assertLessEqual(
        len(test_data['status']), state_manager.MAX_DATASTORE_STRLEN)


class TestRedisEvidenceStateManager(unittest.TestCase):
  """Test PSQStateManager class."""

  def _get_state_manager(self):
    """Gets a Datastore State Manager object for test."""
    config.STATE_MANAGER = 'Redis'
    return state_manager.get_state_manager()

  @mock.patch('turbinia.state_manager.datastore.Client')
  def setUp(self, _):
    self.remove_files = []
    self.remove_dirs = []
    self.state_manager = None

    config.LoadConfig()
    self.state_manager_save = config.STATE_MANAGER

    self.test_data = {
        'TurbiniaEvidence:b510ab6bf11a410da1fd9d9b128e7d74': {
            'request_id': '5581344e306b42ccb965a19028d4fc58',
            'tasks': [
                'b73d484634164e0eb1870d101ca9ce2f',
                'dd810119ac2443e18b69ea56c10c0a9b',
                'ac4dc14080b144478437818a694e2f4d'
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
                    'debug_tasks':
                        False,
                    'jobs_allowlist': [],
                    'jobs_denylist': [],
                    'yara_rules':
                        '',
                    'filter_patterns': [],
                    'sketch_id':
                        None,
                    'group_name':
                        '',
                    'reason':
                        '',
                    'all_args':
                        'turbinia/turbiniactl.py rawdisk -l /workspaces/turbinia/test_data/artifact_disk.dd',
                    'group_id':
                        '55ce6e98dc154e73990b24f0c79ab07e',
                    'requester':
                        'root'
                }
            },
            'tags': {},
            'creation_time': '2023-08-04T19:16:28.182774Z',
            'last_updated': '2023-08-04T19:17:58.769212Z',
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
        },
        'TurbiniaEvidence:e2d9bff0c78b471e820db55080012f44': {
            'request_id':
                '6d6f85f44487441c9d4da1bda56ae90a',
            'tasks': ['c2956426748f434f8c2f0d481e779c7c'],
            'copyable':
                True,
            'cloud_only':
                False,
            'local_path':
                '/evidence/6d6f85f44487441c9d4da1bda56ae90a/1691176629-e8a88832ef954bd59c3b0f50ce2eef85-FileArtifactExtractionTask/export/home/dummyuser/.jupyter/jupyter_notebook_config.py',
            'source_path':
                '/evidence/6d6f85f44487441c9d4da1bda56ae90a/1691176629-e8a88832ef954bd59c3b0f50ce2eef85-FileArtifactExtractionTask/export/home/dummyuser/.jupyter/jupyter_notebook_config.py',
            'resource_tracked':
                False,
            'processed_by': [],
            'artifact_name':
                'JupyterConfigFile',
            'resource_id':
                None,
            'credentials': [],
            'config': {
                'globals': {
                    'debug_tasks':
                        False,
                    'jobs_allowlist': [],
                    'jobs_denylist': [],
                    'yara_rules':
                        '',
                    'filter_patterns': [],
                    'sketch_id':
                        None,
                    'group_name':
                        '',
                    'reason':
                        '',
                    'all_args':
                        'turbinia/turbiniactl.py rawdisk -l /workspaces/turbinia/test_data/artifact_disk.dd',
                    'group_id':
                        '55ce6e98dc154e73990b24f0c79ab07e',
                    'requester':
                        'root'
                }
            },
            'tags': {},
            'creation_time':
                '2023-08-04T19:17:12.650264Z',
            'last_updated':
                '2023-08-04T19:18:02.482149Z',
            'parent_evidence':
                None,
            'size':
                472,
            'saved_path_type':
                None,
            'mount_path':
                None,
            'has_child_evidence':
                False,
            'save_metadata':
                False,
            'type':
                'ExportedFileArtifact',
            'source':
                None,
            'saved_path':
                None,
            '_name':
                None,
            'context_dependent':
                False,
            'state': {},
            'id':
                'e2d9bff0c78b471e820db55080012f44',
            'redis_function':
                None,
            'hash':
                None,
            'description':
                None
        },
        'TurbiniaEvidence:0114968b6293410e818eb1ec72db56f8': {
            'request_id':
                '6d6f85f44487441c9d4da1bda56ae90a',
            'tasks': [],
            'copyable':
                True,
            'cloud_only':
                False,
            'local_path':
                '/evidence/6d6f85f44487441c9d4da1bda56ae90a/1691176675-2d4603b7b401471f99bd7716907c0781-WordpressCredsAnalysisTask/wordpress_creds_analysis.txt',
            'source_path':
                '/evidence/6d6f85f44487441c9d4da1bda56ae90a/1691176675-2d4603b7b401471f99bd7716907c0781-WordpressCredsAnalysisTask/wordpress_creds_analysis.txt',
            'resource_tracked':
                False,
            'processed_by': [],
            'resource_id':
                None,
            'credentials': [],
            'config': {
                'globals': {
                    'debug_tasks':
                        False,
                    'jobs_allowlist': [],
                    'jobs_denylist': [],
                    'yara_rules':
                        '',
                    'filter_patterns': [],
                    'sketch_id':
                        None,
                    'group_name':
                        '',
                    'reason':
                        '',
                    'all_args':
                        'turbinia/turbiniactl.py rawdisk -l /workspaces/turbinia/test_data/artifact_disk.dd',
                    'group_id':
                        '55ce6e98dc154e73990b24f0c79ab07e',
                    'requester':
                        'root'
                }
            },
            'tags': {},
            'creation_time':
                '2023-08-04T19:17:55.547920Z',
            'last_updated':
                '2023-08-04T19:18:08.566615Z',
            'parent_evidence':
                None,
            'size':
                None,
            'saved_path_type':
                None,
            'mount_path':
                None,
            'has_child_evidence':
                False,
            'save_metadata':
                False,
            'type':
                'ReportText',
            'source':
                None,
            'saved_path':
                None,
            '_name':
                None,
            'context_dependent':
                False,
            'state': {
                '1': False,
                '2': False,
                '3': False,
                '4': False
            },
            'id':
                '0114968b6293410e818eb1ec72db56f8',
            'redis_function':
                None,
            'hash':
                None,
            'text_data':
                '',
            'description':
                None
        }
    }

    self.values_sort_summary = {
        '5581344e306b42ccb965a19028d4fc58': [
            self.test_data['TurbiniaEvidence:b510ab6bf11a410da1fd9d9b128e7d74']
        ],
        '6d6f85f44487441c9d4da1bda56ae90a': [
            self.test_data['TurbiniaEvidence:e2d9bff0c78b471e820db55080012f44'],
            self.test_data['TurbiniaEvidence:0114968b6293410e818eb1ec72db56f8']
        ]
    }

    self.keys_sort_summary = {
        '5581344e306b42ccb965a19028d4fc58': [
            'TurbiniaEvidence:b510ab6bf11a410da1fd9d9b128e7d74'
        ],
        '6d6f85f44487441c9d4da1bda56ae90a': [
            'TurbiniaEvidence:e2d9bff0c78b471e820db55080012f44',
            'TurbiniaEvidence:0114968b6293410e818eb1ec72db56f8'
        ]
    }
    self.count_sort_summary = {True: 2, False: 1}

    self.fake_redis_dict = {}

  def hkeys_side_effect(self, key):
    return [
        bytes(attribute_key, 'utf-8') for attribute_key in self.test_data[key]
    ]

  def hget_side_effect(self, name, key):
    if isinstance(name, bytes):
      name = name.decode()
    if isinstance(key, bytes):
      key = key.decode()
    return bytes(json.dumps(self.test_data[name][key]), 'utf-8')

  def hset_side_effect(self, name, key, value):
    if name not in self.fake_redis_dict:
      self.fake_redis_dict[name] = {}
    self.fake_redis_dict[name][key] = value
    return 1

  def get_evidence_side_effect(self, evidence_id):
    return self.test_data[':'.join(('TurbiniaEvidence', evidence_id))]

  @mock.patch('redis.StrictRedis')
  def testStateManagerGetEvidence(self, mock_redis):
    """Test State Manager get_evidence()."""

    evidence_key = 'TurbiniaEvidence:b510ab6bf11a410da1fd9d9b128e7d74'

    self.state_manager = self._get_state_manager()

    mock_redis.return_value.hkeys.side_effect = self.hkeys_side_effect

    mock_redis.return_value.hget.side_effect = self.hget_side_effect

    evidence_dict = self.state_manager.get_evidence(
        self.test_data[evidence_key]['id'])

    # Check if the returned evidence_dict contains all of our test data
    for (test_value, retrieved_value) in zip(
        self.test_data[evidence_key].values(), evidence_dict.values()):
      self.assertEqual(test_value, retrieved_value)
    self.assertIn('tasks', evidence_dict)
    self.assertIn(
        self.test_data[evidence_key]['tasks'][0], evidence_dict['tasks'])

  @mock.patch('redis.StrictRedis')
  def testStateManagerWriteEvidence(self, mock_redis):
    """Test State Manager write_evidence()."""

    evidence_key = 'TurbiniaEvidence:b510ab6bf11a410da1fd9d9b128e7d74'

    self.state_manager = self._get_state_manager()

    mock_redis.return_value.hset.side_effect = self.hset_side_effect

    self.state_manager.write_evidence({
        key: json.dumps(value)
        for key, value in self.test_data[evidence_key].items()
    })

    written_evidence = self.fake_redis_dict[evidence_key]

    # Check if the stored evidence contains all of our test data
    self.assertIn('tasks', written_evidence)
    for (test_value, written_value) in zip(
        self.test_data[evidence_key].values(), written_evidence.values()):
      self.assertEqual(json.dumps(test_value), written_value)
    self.assertIn('tasks', written_evidence)
    self.assertIn(
        self.test_data[evidence_key]['tasks'][0], written_evidence['tasks'])
    self.assertIn('TurbiniaEvidenceHashes', self.fake_redis_dict)
    self.assertEqual(
        self.fake_redis_dict['TurbiniaEvidenceHashes'][
            self.test_data[evidence_key]['hash']], evidence_key)

    # Flushes fake redis
    self.fake_redis_dict = {}

  @mock.patch('redis.StrictRedis')
  def testStateManagerUpdateEvidenceAttribute(self, mock_redis):
    """Test State Manager update_evidence()."""

    evidence_key = 'TurbiniaEvidence:b510ab6bf11a410da1fd9d9b128e7d74'

    self.state_manager = self._get_state_manager()

    mock_redis.return_value.hset.side_effect = self.hset_side_effect

    for attribute_name, attribute_value in self.test_data[evidence_key].items():
      self.state_manager.update_evidence_attribute(
          self.test_data[evidence_key]['id'], attribute_name,
          json.dumps(attribute_value))

    # Tests writting extra attribute
    self.state_manager.update_evidence_attribute(
        self.test_data[evidence_key]['id'], 'test_attribute',
        json.dumps('test_value'))

    written_evidence = self.fake_redis_dict[evidence_key]

    # Check if the stored evidence contains all of our test data
    self.assertIn('tasks', written_evidence)
    for (test_value, written_value) in zip(
        self.test_data[evidence_key].values(), written_evidence.values()):
      self.assertEqual(json.dumps(test_value), written_value)
    self.assertIn('tasks', written_evidence)
    self.assertIn(
        self.test_data[evidence_key]['tasks'][0], written_evidence['tasks'])
    self.assertIn('TurbiniaEvidenceHashes', self.fake_redis_dict)
    self.assertEqual(
        self.fake_redis_dict['TurbiniaEvidenceHashes'][
            self.test_data[evidence_key]['hash']], evidence_key)
    self.assertIn('test_attribute', self.fake_redis_dict[evidence_key])
    self.assertEqual(
        json.dumps('test_value'),
        self.fake_redis_dict[evidence_key]['test_attribute'])

    # Flushes fake redis
    self.fake_redis_dict = {}

  @mock.patch('redis.StrictRedis')
  @mock.patch('turbinia.state_manager.RedisStateManager.get_evidence')
  def testStateManagerEvidenceSummaryValues(
      self, mock_get_evidence, mock_redis):
    """Test State Manager get_evidence()."""

    self.state_manager = self._get_state_manager()

    mock_redis.return_value.scan_iter.return_value = [
        bytes(key, 'utf-8') for key in self.test_data
    ]
    mock_get_evidence.side_effect = self.get_evidence_side_effect

    evidence_values_summary = self.state_manager.get_evidence_summary(
        output='values')

    # Check if the returned summary contains all of our test data
    for (original_evidence, summary_evidence) in zip(self.test_data.values(),
                                                     evidence_values_summary):
      for (original_attribute, summary_attribute) in zip(
          original_evidence.values(), summary_evidence.values()):
        self.assertEqual(original_attribute, summary_attribute)

  @mock.patch('redis.StrictRedis')
  @mock.patch('turbinia.state_manager.RedisStateManager.get_evidence')
  def testStateManagerEvidenceSummaryKeys(self, mock_get_evidence, mock_redis):
    """Test State Manager get_evidence()."""

    self.state_manager = self._get_state_manager()

    mock_redis.return_value.scan_iter.return_value = [
        bytes(key, 'utf-8') for key in self.test_data
    ]
    mock_get_evidence.side_effect = self.get_evidence_side_effect

    evidence_keys_summary = self.state_manager.get_evidence_summary(
        output='keys')

    # Check if the returned summary contains all of our test data
    for (original_key, summary_key) in zip(self.test_data.keys(),
                                           evidence_keys_summary):
      self.assertEqual(original_key, summary_key)

  @mock.patch('redis.StrictRedis')
  def testStateManagerEvidenceSummaryCount(self, mock_redis):
    """Test State Manager get_evidence()."""

    self.state_manager = self._get_state_manager()

    mock_redis.return_value.scan_iter.return_value = [
        bytes(key, 'utf-8') for key in self.test_data
    ]

    evidence_count_summary = self.state_manager.get_evidence_summary(
        output='count')

    # Check if the returned summary contains all of our test data
    self.assertEqual(len(self.test_data), evidence_count_summary)

  @mock.patch('redis.StrictRedis')
  @mock.patch('turbinia.state_manager.RedisStateManager.get_evidence')
  def testStateManagerEvidenceSummaryValuesSort(
      self, mock_get_evidence, mock_redis):
    """Test State Manager get_evidence()."""

    self.state_manager = self._get_state_manager()

    mock_redis.return_value.scan_iter.return_value = [
        bytes(key, 'utf-8') for key in self.test_data
    ]
    mock_get_evidence.side_effect = self.get_evidence_side_effect

    evidence_values_summary = self.state_manager.get_evidence_summary(
        sort='request_id', output='values')

    # Check if the returned summary contains all of our test data
    for key, value in self.values_sort_summary.items():
      for reference_value, summary_value in zip(value,
                                                evidence_values_summary[key]):
        for reference_attribute, summary_attribute in zip(
            reference_value.values(), summary_value.values()):
          self.assertEqual(reference_attribute, summary_attribute)

  @mock.patch('redis.StrictRedis')
  @mock.patch('turbinia.state_manager.RedisStateManager.get_evidence')
  def testStateManagerEvidenceSummaryKeysSort(
      self, mock_get_evidence, mock_redis):
    """Test State Manager get_evidence()."""

    self.state_manager = self._get_state_manager()

    mock_redis.return_value.scan_iter.return_value = [
        bytes(key, 'utf-8') for key in self.test_data
    ]
    mock_get_evidence.side_effect = self.get_evidence_side_effect

    evidence_keys_summary = self.state_manager.get_evidence_summary(
        sort='request_id', output='keys')

    # Check if the returned summary contains all of our test data
    for key, value in self.keys_sort_summary.items():
      for reference_key, summary_key in zip(value, evidence_keys_summary[key]):
        self.assertEqual(reference_key, summary_key)

  @mock.patch('redis.StrictRedis')
  @mock.patch('turbinia.state_manager.RedisStateManager.get_evidence')
  def testStateManagerEvidenceSummaryCountSort(
      self, mock_get_evidence, mock_redis):
    """Test State Manager get_evidence()."""

    self.state_manager = self._get_state_manager()

    mock_redis.return_value.scan_iter.return_value = [
        bytes(key, 'utf-8') for key in self.test_data
    ]
    mock_get_evidence.side_effect = self.get_evidence_side_effect

    evidence_count_summary = self.state_manager.get_evidence_summary(
        sort='copyable', output='count')

    # Check if the returned summary contains all of our test data
    for key, value in self.count_sort_summary.items():
      self.assertEqual(evidence_count_summary[key], value)

  @mock.patch('redis.StrictRedis')
  @mock.patch('turbinia.state_manager.RedisStateManager.get_evidence')
  def testStateManagerEvidenceQueryValues(self, mock_get_evidence, mock_redis):
    """Test State Manager get_evidence()."""

    self.state_manager = self._get_state_manager()

    mock_redis.return_value.hget.side_effect = self.hget_side_effect
    mock_redis.return_value.scan_iter.return_value = [
        bytes(key, 'utf-8') for key in self.test_data
    ]
    mock_get_evidence.side_effect = self.get_evidence_side_effect

    values_query = self.state_manager.query_evidence(
        'request_id', '6d6f85f44487441c9d4da1bda56ae90a', output='values')

    # Check if the returned summary contains all of our test data
    for reference_value, query_value in zip(
        self.values_sort_summary['6d6f85f44487441c9d4da1bda56ae90a'],
        values_query):
      for reference_attribute, query_attribute in zip(reference_value.values(),
                                                      query_value.values()):
        self.assertEqual(reference_attribute, query_attribute)

  @mock.patch('redis.StrictRedis')
  @mock.patch('turbinia.state_manager.RedisStateManager.get_evidence')
  def testStateManagerEvidenceQueryKeys(self, mock_get_evidence, mock_redis):
    """Test State Manager get_evidence()."""

    self.state_manager = self._get_state_manager()

    mock_redis.return_value.hget.side_effect = self.hget_side_effect
    mock_redis.return_value.scan_iter.return_value = [
        bytes(key, 'utf-8') for key in self.test_data
    ]
    mock_get_evidence.side_effect = self.get_evidence_side_effect

    keys_query = self.state_manager.query_evidence(
        'request_id', '6d6f85f44487441c9d4da1bda56ae90a', output='keys')

    # Check if the returned summary contains all of our test data
    for reference_key, query_key in zip(
        self.keys_sort_summary['6d6f85f44487441c9d4da1bda56ae90a'], keys_query):
      self.assertEqual(reference_key, query_key)

  @mock.patch('redis.StrictRedis')
  @mock.patch('turbinia.state_manager.RedisStateManager.get_evidence')
  def testStateManagerEvidenceQueryCount(self, mock_get_evidence, mock_redis):
    """Test State Manager get_evidence()."""

    self.state_manager = self._get_state_manager()

    mock_redis.return_value.hget.side_effect = self.hget_side_effect
    mock_redis.return_value.scan_iter.return_value = [
        bytes(key, 'utf-8') for key in self.test_data
    ]
    mock_get_evidence.side_effect = self.get_evidence_side_effect

    count_query = self.state_manager.query_evidence(
        'copyable', True, output='count')

    # Check if the returned summary contains all of our test data
    self.assertEqual(self.count_sort_summary[True], count_query)
