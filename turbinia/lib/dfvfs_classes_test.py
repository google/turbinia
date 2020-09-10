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

from dfvfs.helpers import source_scanner
import unittest

from turbinia.lib.dfvfs_classes import SourceAnalyzer


class TestSourceAnalyzer(unittest.TestCase):
  """Test SourceAnalyzer class."""

  def setUp(self):
    self.source_analyzer = SourceAnalyzer()

  def testSourceAnalyzerInit(self):
    """Tests __init__ method of SourceAnalyzer."""
    # Test that a SourceScanner is being created
    self.assertIsInstance(
        self.source_analyzer._source_scanner, source_scanner.SourceScanner)

  def testVolumeScan(self):
    """Tests VolumeScan method of SourceAnalyzer."""
