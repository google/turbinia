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
"""Tests for the Fsstat job."""

from __future__ import unicode_literals

import unittest
import mock

from turbinia.evidence import ReportText
from turbinia.workers import fsstat
from turbinia.workers.workers_test import TestTurbiniaTaskBase
from turbinia.workers import TurbiniaTaskResult


class FsstatTaskTest(TestTurbiniaTaskBase):
  """Tests for Fsstat."""

  def setUp(self):
    # pylint: disable=arguments-differ
    super(FsstatTaskTest, self).setUp(
        task_class=fsstat.FsstatTask, evidence_class=ReportText)
    self.setResults(mock_run=False)
    self.task.output_dir = self.task.base_output_dir

  @mock.patch('turbinia.evidence.DiskPartition')
  def testFsstatRun(self, mock_evidence):
    """Test fsstat task run."""
    self.task.execute = mock.MagicMock(return_value=0)
    mock_evidence.path_spec.type_indicator = 'EXT'
    result = self.task.run(mock_evidence, self.result)

    # Ensure execute method is being called.
    self.task.execute.assert_called_once()
    # Ensure run method returns a TurbiniaTaskResult instance.
    self.assertIsInstance(result, TurbiniaTaskResult)

    # Test for XFS
    self.task.execute.reset_mock()
    mock_evidence.path_spec.type_indicator = 'XFS'
    result = self.task.run(mock_evidence, self.result)

    # Ensure execute method is not being called.
    self.task.execute.assert_not_called()
    # Ensure run method returns a TurbiniaTaskResult instance.
    self.assertIsInstance(result, TurbiniaTaskResult)

  @mock.patch('turbinia.evidence.DiskPartition')
  def testFsstatRunNoPathSpec(self, mock_evidence):
    """Test fssstat task on an evidence object with no path_spec."""
    self.task.execute = mock.MagicMock(return_value=0)
    mock_evidence.path_spec = None
    result = self.task.run(mock_evidence, self.result)

    # Ensure execute method is not being called.
    self.task.execute.assert_not_called()
    # Ensure run method returns a TurbiniaTaskResult instance.
    self.assertIsInstance(result, TurbiniaTaskResult)


if __name__ == '__main__':
  unittest.main()
