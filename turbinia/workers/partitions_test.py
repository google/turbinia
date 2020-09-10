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

  @mock.patch('turbinia.lib.dfvfs_classes.SourceAnalyzer.VolumeScan')
  def testPartitionEnumerationRun(self, mock_volumescan):
    """Test PartitionEnumeration task run."""
    mock_volumescan.return_value = {
        'p1': {
            'offset': 1048576,
            'size': 9437184,
            'description': 'NTFS / exFAT (0x07)',
            'volume_type': 'NTFS'
        },
        'p2': {
            'offset': 11534336,
            'size': 9437184,
            'description': 'Linux (0x83)',
            'volume_type': 'TSK'
        }
    }

    result = self.task.run(self.evidence, self.result)

    # Ensure run method returns a TurbiniaTaskResult instance.
    self.assertIsInstance(result, TurbiniaTaskResult)
    self.assertEqual(result.task_name, 'PartitionEnumerationTask')
    self.assertEqual(len(result.evidence), 2)
    expected_report = []
    expected_report.append(
        'Found 2 partition(s) in [{0:s}]:\n'.format(self.evidence.local_path))
    expected_report.append(
        'Identifier     Description                   Type       Offset (bytes)   Size (bytes)   Name (APFS)                   '
    )
    expected_report.append(
        'p1             NTFS / exFAT (0x07)           NTFS              1048576        9437184                                 '
    )
    expected_report.append(
        'p2             Linux (0x83)                  TSK              11534336        9437184                                 '
    )
    expected_report = '\n'.join(expected_report)
    self.assertEqual(result.report_data, expected_report)


if __name__ == '__main__':
  unittest.main()
