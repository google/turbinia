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

import fakeredis
import importlib
import json
import os
import unittest
from unittest import mock

from turbinia import config
from turbinia import state_manager


class TestRedisStateManager(unittest.TestCase):
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
        self.state_manager.redis_client.client.hset(
            evidence_key, attribute_name, json.dumps(attribute_value))

  def get_data_from_fake_redis(self):
    for evidence_key, evidence_value in self.test_data.items():
      for attribute_name, attribute_value in evidence_value.items():
        self.state_manager.redis_client.client.hset(
            evidence_key, attribute_name, json.dumps(attribute_value))

  @mock.patch('redis.StrictRedis')
  @mock.patch('turbinia.state_manager.get_state_manager')
  def setUp(self, _, mock_redis):
    self.state_manager = None
    config.LoadConfig()
    mock_redis = fakeredis.FakeStrictRedis()
    config.STATE_MANAGER = 'Redis'
    # force state_manager module to reload using Redis state manager.
    importlib.reload(state_manager)
    self.state_manager = state_manager.get_state_manager()
    self.state_manager.redis_client.client = mock_redis

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
    for attribute_name, attribute_value in (
        self.state_manager.redis_client.client.hscan_iter(evidence_key)):
      result[attribute_name.decode()] = attribute_value.decode()

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

  def testBuildKeyName(self):
    """Test State Manager build_key_name() method."""
    key_types = ('evidence', 'task', 'request')
    for key_type in key_types:
      key_name = self.state_manager.redis_client.build_key_name(
          key_type, '1234')
      self.assertIsInstance(key_name, str)

  def testBuildInvalidKeyName(self):
    """Test State Manager build_key_name() method, invalid key type"""
    self.assertRaises(
        ValueError, self.state_manager.redis_client.build_key_name, 'wrong',
        '1234')
