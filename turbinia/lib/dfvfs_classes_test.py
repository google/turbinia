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
"""Tests for the dfvfs_classes module."""

import unittest

from dfvfs.helpers import source_scanner
from dfvfs.lib import definitions as dfvfs_definitions
from dfvfs.path import factory as path_spec_factory
from dfvfs.volume import volume_system as dfvfs_volume_system
import mock

from turbinia.lib.dfvfs_classes import UnattendedVolumeScannerMediator


class TestUnattendedVolumeScannerMediator(unittest.TestCase):
  """Test the UnattendedVolumeScannerMediator class."""

  @mock.patch('dfvfs.volume.volume_system.VolumeSystem')
  def testGetAPFSVolumeIdentifiers(self, mock_volumesystem):
    """Test the GetAPFSVolumeIdentifiers function."""
    mediator = UnattendedVolumeScannerMediator()

    type(mock_volumesystem.return_value).number_of_volumes = 1

    volume_system = dfvfs_volume_system.VolumeSystem()
    volume_identifiers = ['apfs1']

    result = mediator.GetAPFSVolumeIdentifiers(
        volume_system, volume_identifiers)

    self.assertEqual(result, volume_identifiers)

  @mock.patch('dfvfs.volume.volume_system.VolumeSystem')
  def testGetPartitionIdentifiers(self, mock_volumesystem):
    """Test the GetPartitionIdentifiers function."""
    mediator = UnattendedVolumeScannerMediator()

    type(mock_volumesystem.return_value).number_of_volumes = 2

    volume_system = dfvfs_volume_system.VolumeSystem()
    volume_identifiers = ['p1', 'p2']

    result = mediator.GetPartitionIdentifiers(volume_system, volume_identifiers)

    self.assertEqual(result, volume_identifiers)

  @mock.patch('dfvfs.volume.volume_system.VolumeSystem')
  def testGetVSSStoreIdentifiers(self, mock_volumesystem):
    """Test the GetVSSStoreIdentifiers function.

    VSS support is not yet implemented.
    """
    mediator = UnattendedVolumeScannerMediator()

    type(mock_volumesystem.return_value).number_of_volumes = 3

    volume_system = dfvfs_volume_system.VolumeSystem()
    volume_identifiers = ['vss1', 'vss2', 'vss3']

    result = mediator.GetVSSStoreIdentifiers(volume_system, volume_identifiers)

    self.assertEqual(result, [])

  def testUnlockEncryptedVolume(self):
    """Test the UnlockEncryptedVolume function.

    Encrypted volume support is not yet implemented.
    """
    mediator = UnattendedVolumeScannerMediator()

    os_path_spec = path_spec_factory.Factory.NewPathSpec(
        dfvfs_definitions.TYPE_INDICATOR_OS, location='/path/to/image.dd')
    raw_path_spec = path_spec_factory.Factory.NewPathSpec(
        dfvfs_definitions.TYPE_INDICATOR_RAW, parent=os_path_spec)
    tsk_partition_path_spec = path_spec_factory.Factory.NewPathSpec(
        dfvfs_definitions.TYPE_INDICATOR_TSK_PARTITION, parent=raw_path_spec)
    path_spec = path_spec_factory.Factory.NewPathSpec(
        dfvfs_definitions.TYPE_INDICATOR_BDE, parent=tsk_partition_path_spec)

    scan_node = source_scanner.SourceScanNode(path_spec)

    result = mediator.UnlockEncryptedVolume(
        source_scanner_object=None, scan_context=None,
        locked_scan_node=scan_node, credentials=None)
    self.assertFalse(result)
