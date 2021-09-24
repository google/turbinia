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

import os
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
        evidence_class=partitions.DiskPartition)
    self.setResults(mock_run=False)

  @mock.patch('turbinia.state_manager.get_state_manager')
  @mock.patch('dfvfs.helpers.volume_scanner.VolumeScanner.GetBasePathSpecs')
  def testPartitionEnumerationRun(self, mock_getbasepathspecs, _):
    """Test PartitionEnumeration task run."""
    self.result.setup(self.task)
    filedir = os.path.dirname(os.path.realpath(__file__))
    test_data = os.path.join(filedir, '..', '..', 'test_data', 'mbr.raw')

    os_path_spec = path_spec_factory.Factory.NewPathSpec(
        dfvfs_definitions.TYPE_INDICATOR_OS, location=test_data)
    raw_path_spec = path_spec_factory.Factory.NewPathSpec(
        dfvfs_definitions.TYPE_INDICATOR_RAW, parent=os_path_spec)
    tsk_p1_spec = path_spec_factory.Factory.NewPathSpec(
        dfvfs_definitions.TYPE_INDICATOR_TSK_PARTITION, parent=raw_path_spec,
        location='/p1', part_index=2, start_offset=512)
    tsk_spec = path_spec_factory.Factory.NewPathSpec(
        dfvfs_definitions.TYPE_INDICATOR_NTFS, parent=tsk_p1_spec, location='/')

    mock_getbasepathspecs.return_value = [tsk_spec]

    result = self.task.run(self.evidence, self.result)

    # Ensure run method returns a TurbiniaTaskResult instance.
    self.assertIsInstance(result, TurbiniaTaskResult)
    self.assertEqual(result.task_name, 'PartitionEnumerationTask')
    self.assertEqual(len(result.evidence), 1)
    expected_report = []
    expected_report.append(
        fmt.heading4(
            'Found 1 partition(s) in [{0:s}]:'.format(
                self.evidence.local_path)))
    expected_report.append(fmt.heading5('/p1:'))
    expected_report.append(fmt.bullet('Filesystem: NTFS'))
    expected_report.append(fmt.bullet('Partition index: 2'))
    expected_report.append(fmt.bullet('Partition offset: 512'))
    expected_report.append(fmt.bullet('Partition size: 66048'))
    expected_report = '\n'.join(expected_report)
    self.assertEqual(result.report_data, expected_report)

  @mock.patch('turbinia.state_manager.get_state_manager')
  @mock.patch('dfvfs.helpers.volume_scanner.VolumeScanner.GetBasePathSpecs')
  def testPartitionEnumerationRunAPFS(self, mock_getbasepathspecs, _):
    """Test PartitionEnumeration task run on APFS."""
    self.result.setup(self.task)
    filedir = os.path.dirname(os.path.realpath(__file__))
    test_data = os.path.join(filedir, '..', '..', 'test_data', 'apfs.raw')

    test_os_path_spec = path_spec_factory.Factory.NewPathSpec(
        dfvfs_definitions.TYPE_INDICATOR_OS, location=test_data)
    test_raw_path_spec = path_spec_factory.Factory.NewPathSpec(
        dfvfs_definitions.TYPE_INDICATOR_RAW, parent=test_os_path_spec)
    test_apfs_container_path_spec = path_spec_factory.Factory.NewPathSpec(
        dfvfs_definitions.TYPE_INDICATOR_APFS_CONTAINER, location='/apfs1',
        volume_index=0, parent=test_raw_path_spec)

    mock_getbasepathspecs.return_value = [test_apfs_container_path_spec]

    result = self.task.run(self.evidence, self.result)

    # Ensure run method returns a TurbiniaTaskResult instance.
    expected_report = []
    expected_report.append(
        fmt.heading4(
            'Found 1 partition(s) in [{0:s}]:'.format(
                self.evidence.local_path)))
    expected_report.append(fmt.heading5('/apfs1:'))
    expected_report.append(fmt.bullet('Filesystem: APFS_CONTAINER'))
    expected_report.append(fmt.bullet('Volume index: 0'))
    expected_report = '\n'.join(expected_report)
    self.assertEqual(result.report_data, expected_report)

  @mock.patch('turbinia.state_manager.get_state_manager')
  @mock.patch('dfvfs.helpers.volume_scanner.VolumeScanner.GetBasePathSpecs')
  def testPartitionEnumerationRunGPT(self, mock_getbasepathspecs, _):
    """Test PartitionEnumeration task run on GPT."""
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

    result = self.task.run(self.evidence, self.result)

    # Ensure run method returns a TurbiniaTaskResult instance.
    expected_report = []
    expected_report.append(
        fmt.heading4(
            'Found 1 partition(s) in [{0:s}]:'.format(
                self.evidence.local_path)))
    expected_report.append(fmt.heading5('/p1:'))
    expected_report.append(fmt.bullet('Filesystem: EXT'))
    expected_report.append(fmt.bullet('Source evidence is a volume image'))
    expected_report = '\n'.join(expected_report)
    self.assertEqual(result.report_data, expected_report)

  @mock.patch('turbinia.state_manager.get_state_manager')
  @mock.patch('dfvfs.helpers.volume_scanner.VolumeScanner.GetBasePathSpecs')
  def testPartitionEnumerationRunLVM(self, mock_getbasepathspecs, _):
    """Test PartitionEnumeration task run on LVM."""
    self.result.setup(self.task)
    filedir = os.path.dirname(os.path.realpath(__file__))
    test_data = os.path.join(filedir, '..', '..', 'test_data', 'lvm.raw')

    test_os_path_spec = path_spec_factory.Factory.NewPathSpec(
        dfvfs_definitions.TYPE_INDICATOR_OS, location=test_data)
    test_raw_path_spec = path_spec_factory.Factory.NewPathSpec(
        dfvfs_definitions.TYPE_INDICATOR_RAW, parent=test_os_path_spec)
    test_lvm_path_spec = path_spec_factory.Factory.NewPathSpec(
        dfvfs_definitions.TYPE_INDICATOR_LVM, location='/lvm1',
        parent=test_raw_path_spec)
    test_xfs_path_spec = path_spec_factory.Factory.NewPathSpec(
        dfvfs_definitions.TYPE_INDICATOR_XFS, location='/',
        parent=test_lvm_path_spec)

    mock_getbasepathspecs.return_value = [test_xfs_path_spec]

    result = self.task.run(self.evidence, self.result)

    # Ensure run method returns a TurbiniaTaskResult instance.
    expected_report = []
    expected_report.append(
        fmt.heading4(
            'Found 1 partition(s) in [{0:s}]:'.format(
                self.evidence.local_path)))
    expected_report.append(fmt.heading5('/lvm1:'))
    expected_report.append(fmt.bullet('Filesystem: XFS'))
    expected_report.append(fmt.bullet('Source evidence is a volume image'))
    expected_report = '\n'.join(expected_report)
    self.assertEqual(result.report_data, expected_report)


if __name__ == '__main__':
  unittest.main()
