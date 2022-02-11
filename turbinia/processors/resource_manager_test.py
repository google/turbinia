# -*- coding: utf-8 -*-
# Copyright 2021 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Tests for resource_manager handler."""

from __future__ import unicode_literals

import unittest
import os
import shutil
import tempfile

import mock

from turbinia import TurbiniaException, config
from turbinia.processors import resource_manager


class TestResourceManager(unittest.TestCase):
  """Test ResourceManager module."""

  def setUp(self):
    """Test setup."""
    config.LoadConfig()
    self.tmp_dir = tempfile.mkdtemp(prefix='turbinia-test-tmp')
    config.RESOURCE_FILE = os.path.join(self.tmp_dir, 'turbinia-state.json')

  def tearDown(self):
    """Tears Down temporary directory."""
    if 'turbinia-test-tmp' in self.tmp_dir:
      shutil.rmtree(self.tmp_dir)

  def testRetrieveStateFile(self):
    """Tests the RetrieveResourceState() method."""
    # Test call was succesful
    self.assertEqual(resource_manager.RetrieveResourceState(), {})

    # Test file was created
    self.assertTrue(os.path.exists(config.RESOURCE_FILE))

    # Test bad resource file
    with open(config.RESOURCE_FILE, 'w') as fh:
      fh.write("blah")
    fh.close()
    self.assertRaises(TurbiniaException, resource_manager.RetrieveResourceState)
    os.remove(config.RESOURCE_FILE)

  def testPreProcessResourceState(self):
    """Tests the PreProcessResourceState() method."""
    resource_id_1 = "resource_id_1"
    task_id_1 = "task_id_1"
    json_out = {resource_id_1: [task_id_1]}

    # Test that the resource id is properly added with associated task
    resource_manager.PreprocessResourceState(resource_id_1, task_id_1)
    self.assertEqual(resource_manager.RetrieveResourceState(), json_out)

    # Test that the additional task id is appended to resource id
    task_id_2 = "task_id_2"
    json_out_2 = {resource_id_1: [task_id_1, task_id_2]}
    resource_manager.PreprocessResourceState(resource_id_1, task_id_2)
    self.assertEqual(resource_manager.RetrieveResourceState(), json_out_2)

    # Test that additional resource id is added into state file
    resource_id_2 = "resource_id_2"
    json_out_3 = {
        resource_id_1: [task_id_1, task_id_2],
        resource_id_2: [task_id_1]
    }
    resource_manager.PreprocessResourceState(resource_id_2, task_id_1)
    self.assertEqual(resource_manager.RetrieveResourceState(), json_out_3)

    # Test that same task id is not duplicated into state file
    resource_manager.PreprocessResourceState(resource_id_2, task_id_1)
    self.assertEqual(resource_manager.RetrieveResourceState(), json_out_3)

  def testPostProcessResourceState(self):
    """Tests the PostProcessResourceState() method."""
    resource_id_1 = "resource_id_1"
    resource_id_2 = "resource_id_2"
    task_id_1 = "task_id_1"
    task_id_2 = "task_id_2"

    # Add test resource ids and task ids into state file
    resource_manager.PreprocessResourceState(resource_id_1, task_id_1)
    resource_manager.PreprocessResourceState(resource_id_1, task_id_2)
    resource_manager.PreprocessResourceState(resource_id_2, task_id_1)

    # Test that task id was removed from resource id
    json_out_1 = {resource_id_1: [task_id_2], resource_id_2: [task_id_1]}
    is_detachable = resource_manager.PostProcessResourceState(
        resource_id_1, task_id_1)
    self.assertEqual(resource_manager.RetrieveResourceState(), json_out_1)
    self.assertEqual(is_detachable, False)

    # Test that resource id was removed from resource state
    json_out_2 = {resource_id_2: [task_id_1]}
    is_detachable = resource_manager.PostProcessResourceState(
        resource_id_1, task_id_2)
    self.assertEqual(resource_manager.RetrieveResourceState(), json_out_2)
    self.assertEqual(is_detachable, True)

    # Test that non existent task did not throw an error
    is_detachable = resource_manager.PostProcessResourceState(
        resource_id_2, task_id_2)
    self.assertEqual(resource_manager.RetrieveResourceState(), json_out_2)
    self.assertEqual(is_detachable, False)

    # Test removing all from resource state
    json_out_3 = {}
    is_detachable = resource_manager.PostProcessResourceState(
        resource_id_2, task_id_1)
    self.assertEqual(resource_manager.RetrieveResourceState(), json_out_3)
    self.assertEqual(is_detachable, True)


if __name__ == '__main__':
  unittest.main()
