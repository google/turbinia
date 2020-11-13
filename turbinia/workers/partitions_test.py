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

import unittest
from dfvfs.lib import definitions as dfvfs_definitions
from dfvfs.path import factory as path_spec_factory
import mock

from turbinia.lib import text_formatter as fmt
from turbinia.workers import partitions
from turbinia.workers import TurbiniaTaskResult
from turbinia.workers.workers_test import TestTurbiniaTaskBase


class PartitionEnumerationTaskTest(TestTurbiniaTaskBase):
  """Tests for PartitionEnumerationTask."""

  def setUp(self):
    # pylint: disable=arguments-differ
    super(PartitionEnumerationTaskTest, self).setUp(
        task_class=partitions.PartitionEnumerationTask,
        evidence_class=partitions.RawDiskPartition)
    self.setResults(mock_run=False)

  @mock.patch('turbinia.state_manager.get_state_manager')
  @mock.patch('dfvfs.helpers.volume_scanner.VolumeScanner.GetBasePathSpecs')
  def testPartitionEnumerationRun(self, mock_getbasepathspecs, _):
    """Test PartitionEnumeration task run."""
    self.result.setup(self.task)
    os_path_spec = path_spec_factory.Factory.NewPathSpec(
        dfvfs_definitions.TYPE_INDICATOR_OS, location='test.dd')
    raw_path_spec = path_spec_factory.Factory.NewPathSpec(
        dfvfs_definitions.TYPE_INDICATOR_RAW, parent=os_path_spec)
    tsk_p1_spec = path_spec_factory.Factory.NewPathSpec(
        dfvfs_definitions.TYPE_INDICATOR_TSK_PARTITION, parent=raw_path_spec,
        location='/p1', part_index=2, start_offset=1048576)
    ntfs_spec = path_spec_factory.Factory.NewPathSpec(
        dfvfs_definitions.TYPE_INDICATOR_NTFS, parent=tsk_p1_spec,
        location='\\')

    tsk_p2_spec = path_spec_factory.Factory.NewPathSpec(
        dfvfs_definitions.TYPE_INDICATOR_TSK_PARTITION, parent=raw_path_spec,
        location='/p2', part_index=6, start_offset=11534336)
    tsk_spec = path_spec_factory.Factory.NewPathSpec(
        dfvfs_definitions.TYPE_INDICATOR_NTFS, parent=tsk_p2_spec, location='/')

    mock_getbasepathspecs.return_value = [ntfs_spec, tsk_spec]

    result = self.task.run(self.evidence, self.result)

    # Ensure run method returns a TurbiniaTaskResult instance.
    self.assertIsInstance(result, TurbiniaTaskResult)
    self.assertEqual(result.task_name, 'PartitionEnumerationTask')
    self.assertEqual(len(result.evidence), 2)
    expected_report = []
    expected_report.append(
        fmt.heading4(
            'Found 2 partition(s) in [{0:s}]:'.format(
                self.evidence.local_path)))
    expected_report.append(fmt.heading5('/p1:'))
    expected_report.append(fmt.bullet('Partition index: 2'))
    expected_report.append(fmt.bullet('Partition offset: 1048576'))
    expected_report.append(fmt.heading5('/p2:'))
    expected_report.append(fmt.bullet('Partition index: 6'))
    expected_report.append(fmt.bullet('Partition offset: 11534336'))
    expected_report = '\n'.join(expected_report)
    self.assertEqual(result.report_data, expected_report)


if __name__ == '__main__':
  unittest.main()
