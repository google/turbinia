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
from dfvfs.lib import definitions as dfvfs_definitions

from turbinia.lib.dfvfs_classes import SourceAnalyzer


class TestSourceAnalyzer(unittest.TestCase):
  """Test SourceAnalyzer class."""

  def setUp(self):
    file_path = os.path.dirname(os.path.realpath(__file__))
    self._apfs_source_path = os.path.join(
        file_path, '..', '..', 'test_data', 'apfs_volume_system.dmg')
    self._tsk_source_path = os.path.join(
        file_path, '..', '..', 'test_data', 'tsk_volume_system.raw')

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
