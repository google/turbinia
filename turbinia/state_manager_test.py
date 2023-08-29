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
import fakeredis
import importlib
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

  @mock.patch('turbinia.state_manager.datastore.Client')
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
  """Test RedisStateManager class."""

  def get_evidence_data(self):
    with open(os.path.join(os.path.dirname(__file__), '..', 'test_data',
                           'state_manager_test_data.json'), 'r',
              encoding='utf-8') as test_data:
      test_data = test_data.read()
      self.test_data = json.loads(test_data)

    self.grouped_content_summary = {
        '6d6f85f44487441c9d4da1bda56ae90a': [
            self.test_data['TurbiniaEvidence:0114968b6293410e818eb1ec72db56f8'],
            self.test_data['TurbiniaEvidence:e2d9bff0c78b471e820db55080012f44']
        ],
        '5581344e306b42ccb965a19028d4fc58': [
            self.test_data['TurbiniaEvidence:b510ab6bf11a410da1fd9d9b128e7d74']
        ]
    }
    self.grouped_keys_summary = {
        '6d6f85f44487441c9d4da1bda56ae90a': [
            'TurbiniaEvidence:0114968b6293410e818eb1ec72db56f8',
            'TurbiniaEvidence:e2d9bff0c78b471e820db55080012f44'
        ],
        '5581344e306b42ccb965a19028d4fc58': [
            'TurbiniaEvidence:b510ab6bf11a410da1fd9d9b128e7d74'
        ]
    }

    self.grouped_count_summary = {True: 2, False: 1}

  def write_evidence_in_fake_redis(self):
    for evidence_key, evidence_value in self.test_data.items():
      for attribute_name, attribute_value in evidence_value.items():
        self.state_manager.client.hset(
            evidence_key, attribute_name, json.dumps(attribute_value))

  def get_data_from_fake_redis(self):
    for evidence_key, evidence_value in self.test_data.items():
      for attribute_name, attribute_value in evidence_value.items():
        self.state_manager.client.hset(
            evidence_key, attribute_name, json.dumps(attribute_value))

  @mock.patch('redis.StrictRedis')
  @mock.patch('turbinia.state_manager.datastore.Client')
  def setUp(self, _, mock_redis):
    self.state_manager = None
    config.LoadConfig()
    self.state_manager_save = config.STATE_MANAGER

    mock_redis = fakeredis.FakeStrictRedis()
    config.STATE_MANAGER = 'Redis'
    # force state_manager module to reload using Redis state manager.
    importlib.reload(state_manager)
    self.state_manager = state_manager.get_state_manager()
    self.state_manager.set_client(mock_redis)

    self.get_evidence_data()

  def testStateManagerGetEvidenceData(self):
    """Test State Manager get_evidence_data()."""
    self.write_evidence_in_fake_redis()

    evidence_key = 'TurbiniaEvidence:b510ab6bf11a410da1fd9d9b128e7d74'
    input_evidence = self.test_data[evidence_key]

    result = self.state_manager.get_evidence_data(input_evidence['id'])

    # Check if the returned evidence_dict contains all of our test data
    self.assertEqual(input_evidence, result)

  def testStateManagerWriteEvidence(self):
    """Test State Manager write_evidence()."""
    evidence_key = 'TurbiniaEvidence:b510ab6bf11a410da1fd9d9b128e7d74'

    json_dumped_evidence = {
        key: json.dumps(value)
        for key, value in self.test_data[evidence_key].items()
    }

    self.state_manager.write_evidence(json_dumped_evidence)

    result = {}
    for attribute_name, attribute_value in self.state_manager.client.hscan_iter(
        evidence_key):
      result[attribute_name.decode()] = attribute_value.decode()

    null_keys = []
    for key, value in json_dumped_evidence.items():
      if value in ('null', '[]', '{}'):
        null_keys.append(key)
    for key in null_keys:
      json_dumped_evidence.pop(key)

    # Check if the stored evidence contains all of our test data
    self.assertEqual(result, json_dumped_evidence)

  def testStateManagerEvidenceSummaryContent(self):
    """Test State Manager get_evidence_summary() outputting content."""

    self.write_evidence_in_fake_redis()

    result = self.state_manager.get_evidence_summary(output='content')

    # Check if the returned summary contains all of our test data
    self.assertEqual(len(result), len(self.test_data))
    for result_evidence_dict in result:
      evidence_id = result_evidence_dict['id']
      self.assertEqual(
          result_evidence_dict,
          self.test_data[f'TurbiniaEvidence:{evidence_id}'])

  def testStateManagerEvidenceSummaryKeys(self):
    """Test State Manager get_evidence_summary() outputting keys."""

    self.write_evidence_in_fake_redis()

    result = self.state_manager.get_evidence_summary(output='keys')

    # Check if the returned summary contains all of our test data
    self.assertEqual(
        result.sort(), [key for key in self.test_data.keys()].sort())

  def testStateManagerEvidenceSummaryCount(self):
    """Test State Manager get_evidence_summary() outputting count."""

    self.write_evidence_in_fake_redis()

    result = self.state_manager.get_evidence_summary(output='count')

    # Check if the returned summary contains all of our test data
    self.assertEqual(result, len(self.test_data))

  def testStateManagerEvidenceSummaryContentGroup(self):
    """Test State Manager grouped get_evidence_summary() outputting content."""
    self.write_evidence_in_fake_redis()

    result = self.state_manager.get_evidence_summary(
        group='request_id', output='content')

    # Check if the returned summary contains all of our test data
    self.assertEqual(result, self.grouped_content_summary)

  def testStateManagerEvidenceSummaryKeysGroup(self):
    """Test State Manager grouped get_evidence_summary() outputting keys."""
    self.write_evidence_in_fake_redis()

    result = self.state_manager.get_evidence_summary(
        group='request_id', output='keys')

    # Check if the returned summary contains all of our test data
    self.assertEqual(result, self.grouped_keys_summary)

  def testStateManagerEvidenceSummaryCountGroup(self):
    """Test State Manager grouped get_evidence_summary() outputting count."""
    self.write_evidence_in_fake_redis()

    result = self.state_manager.get_evidence_summary(
        group='copyable', output='count')

    # Check if the returned summary contains all of our test data
    self.assertEqual(result, self.grouped_count_summary)

  def testStateManagerEvidenceQueryContent(self):
    """Test State Manager query_evidence() outputting content."""

    self.write_evidence_in_fake_redis()

    result = self.state_manager.query_evidence(
        'request_id', '6d6f85f44487441c9d4da1bda56ae90a', output='content')

    # Check if the returned evidence contains all of our test data
    self.assertEqual(
        result,
        self.grouped_content_summary['6d6f85f44487441c9d4da1bda56ae90a'])

  def testStateManagerEvidenceQueryKeys(self):
    """Test State Manager query_evidence() outputting keys."""

    self.write_evidence_in_fake_redis()

    result = self.state_manager.query_evidence(
        'request_id', '6d6f85f44487441c9d4da1bda56ae90a', output='keys')

    # Check if the returned keys contains all of our test data
    self.assertEqual(
        result, self.grouped_keys_summary['6d6f85f44487441c9d4da1bda56ae90a'])

  def testStateManagerEvidenceQueryCount(self):
    """Test State Manager query_evidence() outputting count."""

    self.write_evidence_in_fake_redis()

    result = self.state_manager.query_evidence('copyable', True, output='count')

    # Check if the returned count is equal to our test data
    self.assertEqual(result, self.grouped_count_summary[True])
