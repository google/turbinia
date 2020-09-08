# -*- coding: utf-8 -*-
# Copyright 2020 Google LLC
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
"""Tests for the Partition Enumeration job."""

import mock
import unittest

from turbinia.workers import partitions
from turbinia.workers import TurbiniaTaskResult
from turbinia.workers.workers_test import TestTurbiniaTaskBase


class PartitionEnumerationTaskTest(TestTurbiniaTaskBase):
  """Tests for PartitionEnumerationTask."""

  def setUp(self):
    super(PartitionEnumerationTaskTest, self).setUp(
        task_class=partitions.PartitionEnumerationTask,
        evidence_class=partitions.RawDiskPartition)
    self.setResults(mock_run=False)

  @mock.patch('turbinia.lib.dfvfs.SourceAnalyzer.Analyze')
  def testPartitionEnumerationRun(self, mock_analyze):
    """Test PartitionEnumeration task run."""
    mock_analyze.return_value = {
        'p1': {
            'description': 'NTFS / exFAT (0x07)',
            'offset': 1048576,
            'size': 9437184
        },
        'p2': {
            'description': 'Linux (0x83)',
            'offset': 11534336,
            'size': 9437184
        }
    }

    result = self.task.run(self.evidence, self.result)

    # Ensure run method returns a TurbiniaTaskResult instance.
    self.assertIsInstance(result, TurbiniaTaskResult)
    self.assertEqual(result.task_name, 'PartitionEnumerationTask')
    self.assertEqual(len(result.evidence), 2)
    self.assertEqual(
        result.report_data,
        'Found 2 partition(s) in [{0:s}]'.format(self.evidence.local_path))


if __name__ == '__main__':
  unittest.main()
