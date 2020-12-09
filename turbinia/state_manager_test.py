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
import os
import tempfile
import unittest
import mock

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
        'status': 'TestStatus',
        'saved_paths': ['testpath1', 'testpath2']
    }

    # Set up TurbiniaTask
    self.base_output_dir = tempfile.mkdtemp()
    self.task = TurbiniaTask(
        base_output_dir=self.base_output_dir, name=self.test_data['name'],
        request_id=self.test_data['request_id'])
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
    """Test State Manger get_task_dict()."""
    self.state_manager = self._get_state_manager()

    task_dict = self.state_manager.get_task_dict(self.task)

    # Make the returned task_dict contains all of our test data
    self.assertEqual(task_dict['name'], self.test_data['name'])
    self.assertEqual(task_dict['request_id'], self.test_data['request_id'])
    self.assertEqual(task_dict['status'], self.test_data['status'])
    self.assertEqual(len(task_dict['saved_paths']), 2)
    self.assertTrue('instance' in task_dict)
    self.assertIn(self.test_data['saved_paths'][0], task_dict['saved_paths'])

  @mock.patch('turbinia.state_manager.datastore.Client')
  def testStateManagerValidateDataValidDict(self, _):
    """Test State Manger _validate_data() base case."""
    self.state_manager = self._get_state_manager()
    # pylint: disable=protected-access
    test_data = self.state_manager._validate_data(self.test_data)
    self.assertDictEqual(test_data, self.test_data)

  @mock.patch('turbinia.state_manager.datastore.Client')
  def testStateManagerValidateDataInvalidDict(self, _):
    """Test State Manger _validate_data() base case."""
    self.state_manager = self._get_state_manager()
    invalid_dict = copy.deepcopy(self.test_data)
    invalid_dict['status'] = 'A' * state_manager.MAX_DATASTORE_STRLEN + 'BORKEN'
    # pylint: disable=protected-access
    test_data = self.state_manager._validate_data(invalid_dict)
    self.assertListEqual(list(test_data.keys()), list(self.test_data.keys()))
    self.assertNotEqual(test_data['status'], self.test_data['status'])
    self.assertLessEqual(
        len(test_data['status']), state_manager.MAX_DATASTORE_STRLEN)
