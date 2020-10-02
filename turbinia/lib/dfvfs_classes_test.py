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

import os
import unittest
from dfvfs.helpers import source_scanner
from dfvfs.lib import definitions as dfvfs_definitions
from dfvfs.path import factory as path_spec_factory
from dfvfs.volume import tsk_volume_system

from turbinia.lib.dfvfs_classes import SourceAnalyzer


class TestSourceAnalyzer(unittest.TestCase):
  """Test the SourceAnalyzer class."""

  def setUp(self):
    file_path = os.path.dirname(os.path.realpath(__file__))
    self._apfs_source_path = os.path.join(
        file_path, '..', '..', 'test_data', 'apfs_volume_system.dmg')
    self._tsk_source_path = os.path.join(
        file_path, '..', '..', 'test_data', 'tsk_volume_system.raw')

  def _GetScanNode(self, scan_context):
    """Retrievs the scan node from the scan context.

    Args:
      scan_context (dfvfs.ScanContext): Source scan context.

    Returns:
      Extracted scan node.
    """
    scan_node = scan_context.GetRootScanNode()
    while len(scan_node.sub_nodes) == 1:
      scan_node = scan_node.sub_nodes[0]
    return scan_node

  def testGetVolumeIdentifiers(self):
    """Tests the _GetVolumeIdentifiers function."""
    source_analyzer = SourceAnalyzer()

    # Test error conditions.
    with self.assertRaises(RuntimeError):
      source_analyzer._GetVolumeIdentifiers(
          None, dfvfs_definitions.TYPE_INDICATOR_APFS_CONTAINER)

    scan_node = source_scanner.SourceScanNode(None)
    with self.assertRaises(RuntimeError):
      source_analyzer._GetVolumeIdentifiers(
          scan_node, dfvfs_definitions.TYPE_INDICATOR_TSK_PARTITION)

    with self.assertRaises(RuntimeError):
      source_analyzer._GetVolumeIdentifiers(scan_node, '')

  def testNormalizedVolumeIdentifiers(self):
    """Tests the _NormalizedVolumeIdentifiers function."""
    source_analyzer = SourceAnalyzer()

    os_path_spec = path_spec_factory.Factory.NewPathSpec(
        dfvfs_definitions.TYPE_INDICATOR_OS, location=self._tsk_source_path)
    raw_path_spec = path_spec_factory.Factory.NewPathSpec(
        dfvfs_definitions.TYPE_INDICATOR_RAW, parent=os_path_spec)
    tsk_partition_path_spec = path_spec_factory.Factory.NewPathSpec(
        dfvfs_definitions.TYPE_INDICATOR_TSK_PARTITION, parent=raw_path_spec)

    volume_system = tsk_volume_system.TSKVolumeSystem()
    volume_system.Open(tsk_partition_path_spec)

    volume_identifiers = source_analyzer._NormalizedVolumeIdentifiers(
        volume_system, ['p1', 'p2'], prefix='p')
    self.assertEqual(volume_identifiers, ['p1', 'p2'])

    volume_identifiers = source_analyzer._NormalizedVolumeIdentifiers(
        volume_system, [1, 2], prefix='p')
    self.assertEqual(volume_identifiers, ['p1', 'p2'])

    volume_identifiers = source_analyzer._NormalizedVolumeIdentifiers(
        volume_system, ['1', '2'], prefix='p')
    self.assertEqual(volume_identifiers, ['p1', 'p2'])

    # Test error conditions.
    with self.assertRaises(RuntimeError):
      source_analyzer._NormalizedVolumeIdentifiers(
          volume_system, ['p3'], prefix='p')

  def testScanFileSystem(self):
    """Tests the _ScanFileSystem method of SourceAnalyzer."""
    source_analyzer = SourceAnalyzer()

    # Test error conditions.
    with self.assertRaises(RuntimeError):
      source_analyzer._ScanFileSystem(None, [])

    scan_node = source_scanner.SourceScanNode(None)
    with self.assertRaises(RuntimeError):
      source_analyzer._ScanFileSystem(scan_node, [])

  def testScanSourceAPFSImage(self):
    """Tests ScanSource method of SourceAnalyzer on an APFS image."""
    source_analyzer = SourceAnalyzer()

    path_specs = source_analyzer.ScanSource(self._apfs_source_path)
    self.assertIsNotNone(path_specs)

    self.assertEqual(len(path_specs), 1)

    path_spec = path_specs[0]
    self.assertEqual(
        path_spec.type_indicator, dfvfs_definitions.TYPE_INDICATOR_APFS)

    path_spec = path_spec.parent
    self.assertEqual(
        path_spec.type_indicator,
        dfvfs_definitions.TYPE_INDICATOR_APFS_CONTAINER)
    self.assertEqual(path_spec.location, '/apfs1')

    path_spec = path_spec.parent
    self.assertEqual(
        path_spec.type_indicator,
        dfvfs_definitions.TYPE_INDICATOR_TSK_PARTITION)
    self.assertEqual(path_spec.start_offset, 20480)

  def testScanSourceTSKImage(self):
    """Tests ScanSource method of SourceAnalyzer on a partitioned image."""
    source_analyzer = SourceAnalyzer()

    path_specs = source_analyzer.ScanSource(self._tsk_source_path)
    self.assertIsNotNone(path_specs)

    self.assertEqual(len(path_specs), 1)

    path_spec = path_specs[0]
    self.assertEqual(
        path_spec.type_indicator, dfvfs_definitions.TYPE_INDICATOR_TSK)

    path_spec = path_spec.parent
    self.assertEqual(
        path_spec.type_indicator,
        dfvfs_definitions.TYPE_INDICATOR_TSK_PARTITION)
    self.assertEqual(path_spec.location, '/p2')
    self.assertEqual(path_spec.start_offset, 180224)

  def testScanVolume(self):
    """Tests the _ScanVolume function."""
    source_analyzer = SourceAnalyzer()

    scan_context = source_scanner.SourceScannerContext()

    # Test error conditions.
    with self.assertRaises(RuntimeError):
      source_analyzer._ScanVolume(scan_context, None, [])

    scan_node = source_scanner.SourceScanNode(None)
    with self.assertRaises(RuntimeError):
      source_analyzer._ScanVolume(scan_context, scan_node, [])

  def testScanVolumeAPFS(self):
    """Tests the _ScanVolume function on an APFS image."""
    source_analyzer = SourceAnalyzer()

    scan_context = source_scanner.SourceScannerContext()
    scan_context.OpenSourcePath(self._apfs_source_path)

    source_analyzer._source_scanner.Scan(scan_context)
    scan_node = self._GetScanNode(scan_context)

    apfs_container_scan_node = scan_node.sub_nodes[4].sub_nodes[0]

    # Test on volume system root node.
    base_path_specs = []
    source_analyzer._ScanVolume(
        scan_context, apfs_container_scan_node, base_path_specs)
    self.assertEqual(len(base_path_specs), 1)

    # Test on volume system sub node.
    base_path_specs = []
    source_analyzer._ScanVolume(
        scan_context, apfs_container_scan_node.sub_nodes[0], base_path_specs)
    self.assertEqual(len(base_path_specs), 1)

  def testScanVolumeSystemRoot(self):
    """Tests the _ScanVolumeSystemRoot function."""
    source_analyzer = SourceAnalyzer()

    scan_context = source_scanner.SourceScannerContext()

    # Test error conditions.
    with self.assertRaises(RuntimeError):
      source_analyzer._ScanVolumeSystemRoot(scan_context, None, [])

    scan_node = source_scanner.SourceScanNode(None)
    with self.assertRaises(RuntimeError):
      source_analyzer._ScanVolumeSystemRoot(scan_context, scan_node, [])

  def testScanVolumeSystemRootAPFS(self):
    """Tests the _ScanVolumeSystemRoot function on an APFS image."""
    source_analyzer = SourceAnalyzer()

    scan_context = source_scanner.SourceScannerContext()
    scan_context.OpenSourcePath(self._apfs_source_path)

    source_analyzer._source_scanner.Scan(scan_context)
    scan_node = self._GetScanNode(scan_context)

    apfs_container_scan_node = scan_node.sub_nodes[4].sub_nodes[0]

    base_path_specs = []
    source_analyzer._ScanVolumeSystemRoot(
        scan_context, apfs_container_scan_node, base_path_specs)
    self.assertEqual(len(base_path_specs), 1)

    # Test error conditions.
    with self.assertRaises(RuntimeError):
      source_analyzer._ScanVolumeSystemRoot(
          scan_context, apfs_container_scan_node.sub_nodes[0], base_path_specs)

  def testScanVolumeSystemRootPartitionedImage(self):
    """Tests the _ScanVolumeSystemRoot function on a partitioned image."""
    source_analyzer = SourceAnalyzer()

    scan_context = source_scanner.SourceScannerContext()
    scan_context.OpenSourcePath(self._tsk_source_path)

    source_analyzer._source_scanner.Scan(scan_context)
    scan_node = self._GetScanNode(scan_context)

    # Test error conditions.
    with self.assertRaises(RuntimeError):
      source_analyzer._ScanVolumeSystemRoot(scan_context, scan_node, [])
