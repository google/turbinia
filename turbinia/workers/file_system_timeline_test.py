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
"""Tests for the FileSystemTimelineJob job."""

from __future__ import unicode_literals

import glob
import unittest
import os
import mock

from turbinia.evidence import BodyFile
from turbinia.workers import file_system_timeline
from turbinia.workers import TurbiniaTaskResult
from turbinia.workers.workers_test import TestTurbiniaTaskBase

from dfvfs.lib import definitions as dfvfs_definitions
from dfvfs.path import factory as path_spec_factory


class FileSystemTimelineTest(TestTurbiniaTaskBase):
  """Tests for FileSystemTimelineJob."""

  def setUp(self):
    super(FileSystemTimelineTest, self).setUp(
        task_class=file_system_timeline.FileSystemTimelineTask,
        evidence_class=BodyFile)
    self.setResults(mock_run=False)
    self.task.output_dir = self.task.base_output_dir

  @mock.patch('turbinia.state_manager.get_state_manager')
  @mock.patch('dfvfs.helpers.volume_scanner.VolumeScanner.GetBasePathSpecs')
  def testRun(self, mock_getbasepathspecs, _):
    """Test FileSystemTimelineJob task run."""
    self.result.setup(self.task)
    filedir = os.path.dirname(os.path.realpath(__file__))
    test_data = os.path.join(filedir, '..', '..', 'test_data', 'gpt.raw')

    test_os_path_spec = path_spec_factory.Factory.NewPathSpec(
        dfvfs_definitions.TYPE_INDICATOR_OS, location=test_data)
    test_raw_path_spec = path_spec_factory.Factory.NewPathSpec(
        dfvfs_definitions.TYPE_INDICATOR_RAW, parent=test_os_path_spec)
    test_gpt_path_spec = path_spec_factory.Factory.NewPathSpec(
        dfvfs_definitions.TYPE_INDICATOR_GPT, location='/p1',
        parent=test_raw_path_spec)
    test_ext_path_spec = path_spec_factory.Factory.NewPathSpec(
        dfvfs_definitions.TYPE_INDICATOR_EXT, location='/',
        parent=test_gpt_path_spec)

    mock_getbasepathspecs.return_value = [test_ext_path_spec]
    self.task = file_system_timeline.FileSystemTimelineTask(
        base_output_dir='/tmp/bodyfile')
    self.task.output_dir = self.base_output_dir
    self.remove_files.append(self.task.output_dir + '/file_system.bodyfile')
    result = self.task.run(self.evidence, self.result)

    # Check the task name.
    task_name = result.task_name
    self.assertEqual(task_name, 'FileSystemTimelineTask')

    # Check the bodyfile contains the expected file entries.
    number_of_entries = result.evidence[0].number_of_entries
    self.assertEqual(number_of_entries, 7)

    # Ensure run method returns a TurbiniaTaskResult instance.
    self.assertIsInstance(result, TurbiniaTaskResult)


if __name__ == '__main__':
  unittest.main()
