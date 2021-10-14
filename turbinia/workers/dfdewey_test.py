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
"""Tests for the dfDewey job."""

from __future__ import unicode_literals

import unittest
import mock

from turbinia.evidence import ReportText
from turbinia.workers import dfdewey
from turbinia.workers import TurbiniaTaskResult
from turbinia.workers.workers_test import TestTurbiniaTaskBase


class DfdeweyTaskTest(TestTurbiniaTaskBase):
  """Tests for dfDewey."""

  def setUp(self):
    # pylint: disable=arguments-differ
    super(DfdeweyTaskTest, self).setUp(
        task_class=dfdewey.DfdeweyTask, evidence_class=ReportText)
    self.setResults(mock_run=False)
    self.task.output_dir = self.task.base_output_dir

  @mock.patch('turbinia.evidence.RawDisk')
  def testDfdeweyRun(self, mock_evidence):
    """Test dfDewey task run."""
    mock_evidence.local_path = 'test.dd'
    self.task.execute = mock.MagicMock(return_value=(0, None))

    # Test with no case
    self.task.run(mock_evidence, self.result)
    # Ensure execute method is not being called.
    self.task.execute.assert_not_called()

    # Test with case
    self.task.task_config['case'] = 'test'
    result = self.task.run(mock_evidence, self.result)
    # Ensure execute method is being called.
    self.task.execute.assert_called_once()
    # Ensure run method returns a TurbiniaTaskResult instance.
    self.assertIsInstance(result, TurbiniaTaskResult)

    # Test search
    self.task.execute.reset_mock()
    self.task.task_config['search'] = 'password'
    result = self.task.run(mock_evidence, self.result)
    # Ensure execute method is being called.
    self.task.execute.assert_called_once()

    # Test failed execution
    self.task.execute = mock.MagicMock(return_value=(1, None))
    result = self.task.run(mock_evidence, self.result)
    # Ensure run method returns a TurbiniaTaskResult instance.
    self.assertIsInstance(result, TurbiniaTaskResult)


if __name__ == '__main__':
  unittest.main()
