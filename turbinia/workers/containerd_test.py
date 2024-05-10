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
"""Tests for ContainerdEnumerationTask."""

import unittest
import mock

from turbinia.evidence import ContainerdContainer
from turbinia.workers.containerd import ContainerdEnumerationTask
from turbinia.workers.workers_test import TestTurbiniaTaskBase
from turbinia.workers import TurbiniaTaskResult


class ContainerdEnumerationTaskTest(TestTurbiniaTaskBase):
  """Tests for ContainerdEnumerationTask."""

  def setUp(self):
    super(ContainerdEnumerationTaskTest, self).setUp(
        task_class=ContainerdEnumerationTask,
        evidence_class=ContainerdContainer)
    self.setResults(mock_run=False)
    self.task.output_dir = self.task.base_output_dir
    self.evidence.mount_path = 'non_existent'

  @mock.patch('turbinia.state_manager.get_state_manager')
  @mock.patch(
      'turbinia.workers.containerd.ContainerdEnumerationTask.list_containers')
  def testContainerdEnumerationTaskRun(self, list_containers_mock, _):
    """Test ContainerdEnumerationTask run."""
    self.result.setup(self.task)

    list_containers_mock.return_value = [
        {
            'Namespace': 'default',
            'ID': 'nginx01',
            'Image': 'nginx01-image',
        },
        {
            'Namespace': 'default',
            'ID': 'apache01',
            'Image': 'apache01-image',
        },
    ]
    result = self.task.run(self.evidence, self.result)

    # Ensure run method returns a TurbiniaTaskResult instance.
    self.assertIsInstance(result, TurbiniaTaskResult)
    self.assertEqual(result.task_name, 'ContainerdEnumerationTask')
    self.assertEqual(len(result.evidence), 2)
    self.assertEqual(
        result.report_data, 'Found 2 containers: nginx01, apache01')


if __name__ == '__main__':
  unittest.main()
