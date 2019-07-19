# -*- coding: utf-8 -*-
# Copyright 2015 Google Inc.
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
"""Tests for VolatilityTask."""

from __future__ import unicode_literals

import os
import mock

from turbinia.evidence import RawMemory
from turbinia.workers.workers_test import TestTurbiniaTaskBase
from turbinia.workers import volatility


class VolatilityTaskTest(TestTurbiniaTaskBase):
  """Tests for VolatilityTask."""

  def setUp(self):
    super(VolatilityTaskTest, self).setUp(
        task_class=volatility.VolatilityTask, evidence_class=RawMemory)
    self.original_max_report_size = volatility.MAX_REPORT_SIZE
    self.evidence.profile = 'TestProfile'
    self.evidence.module_list = ['TestModule']
    self.task.output_dir = self.task.base_output_dir
    self.output_file_path = os.path.join(
        self.task.output_dir, '{0:s}.txt'.format(self.task.id))
    self.remove_files.append(self.output_file_path)
    self.setResults(mock_run=False)

  def tearDown(self):
    super(VolatilityTaskTest, self).tearDown()
    volatility.MAX_REPORT_SIZE = self.original_max_report_size

  def testVolatilityTaskRun(self):
    """Test successful volatility task run."""
    file_contents = 'Test file contents'
    self.task.execute = mock.MagicMock(return_value=0)
    with open(self.output_file_path, 'w') as fh:
      fh.write(file_contents)
    self.task.run(self.evidence, self.result)

    self.assertEqual(file_contents, self.result.report_data)
    self.result.close.assert_called_with(
        self.task, success=True, status=mock.ANY)

  def testVolatilityTaskRunLargeOutput(self):
    """Test volatility run with large output."""
    volatility.MAX_REPORT_SIZE = 9
    file_contents = 'Test file contents'
    truncated_file_contents = file_contents[:volatility.MAX_REPORT_SIZE]
    self.task.execute = mock.MagicMock(return_value=0)
    with open(self.output_file_path, 'w') as fh:
      fh.write(file_contents)
    self.task.run(self.evidence, self.result)

    self.assertEqual(truncated_file_contents, self.result.report_data)
    self.result.close.assert_called_with(
        self.task, success=True, status=mock.ANY)

  def testVolatilityTaskRunNoOutput(self):
    """Test volatility task run with no output."""
    self.task.execute = mock.MagicMock(return_value=0)
    self.task.run(self.evidence, self.result)

    self.assertEqual(None, self.result.report_data)
    self.result.close.assert_called_with(
        self.task, success=False, status=mock.ANY)
