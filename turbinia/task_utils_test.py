# -*- coding: utf-8 -*-
# Copyright 2021 Google Inc.
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
"""Tests for Turbinia task_utils module."""

import unittest
import mock

from turbinia import task_utils
from turbinia.workers.plaso import PlasoParserTask


class TestTurbiniaTaskLoader(unittest.TestCase):
  """Test Turbinia task_utils module."""

  def testCheckTaskNames(self):
    """Basic test for Turbinia get_task_names."""
    task_loader = task_utils.TaskLoader()

    # Check valid task
    self.assertTrue(task_loader.check_task_name('PlasoParserTask'))

    # Check invalid task
    self.assertFalse(task_loader.check_task_name('NoSuchTask'))

  def testGetTaskNames(self):
    """Basic test for get_task_names."""
    task_loader = task_utils.TaskLoader()
    task_names = task_loader.get_task_names()
    self.assertIn('PlasoParserTask', task_names)

  def testGetTask(self):
    """Basic test for get_task."""
    task_loader = task_utils.TaskLoader()

    # Check valid Task
    task = task_loader.get_task('PlasoParserTask')
    self.assertEqual(task.name, 'PlasoParserTask')
    self.assertIsInstance(task, PlasoParserTask)

    # Check invalid Task
    self.assertIsNone(task_loader.get_task('NoSuchTask'))

  def testTaskDeserialize(self):
    """Basic test for task_deserialize."""
    task = PlasoParserTask(
        request_id='testRequestID', requester='testRequester')
    task_dict = task.serialize()
    test_task = task_utils.task_deserialize(task_dict)
    self.assertEqual(test_task.request_id, 'testRequestID')
    self.assertEqual(test_task.requester, 'testRequester')
    self.assertIsInstance(test_task, PlasoParserTask)

  @mock.patch('turbinia.task_utils.task_deserialize')
  def testTaskRunner(self, mock_task_deserialize):
    """Basic test for task_runner."""
    task = PlasoParserTask()
    task.run_wrapper = lambda x: x
    mock_task_deserialize.return_value = task
    task_dict = task.serialize()
    ret = task_utils.task_runner(task_dict, 'testValue')
    self.assertEqual(ret, 'testValue')
