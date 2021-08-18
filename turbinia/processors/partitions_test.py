# -*- coding: utf-8 -*-
# Copyright 2021 Google LLC
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
"""Tests for the Partitions processor."""

import os
import unittest

from turbinia import evidence
from turbinia import TurbiniaException
from turbinia.processors import partitions


class PartitionsProcessorTest(unittest.TestCase):
  """Tests for partitions processor."""

  def _getTestDataPath(self, filename):
    """Returns the full path to test data given a filename.

    Args:
      filename: Test data filename.
    
    Returns:
      String containing the full path to the test data.
    """
    filedir = os.path.dirname(os.path.realpath(__file__))
    test_path = os.path.join(filedir, '..', '..', 'test_data', filename)
    return test_path

  def testEnumerateOnAPFS(self):
    """Test Enumerate on APFS."""
    test_path = self._getTestDataPath('apfs.raw')
    test_evidence = evidence.RawDisk(source_path=test_path)
    path_specs = partitions.Enumerate(test_evidence)
    self.assertEqual(len(path_specs), 1)

  def testEnumerateOnEncryptedAPFS(self):
    """Test Enumerate on encrypted APFS."""
    test_path = self._getTestDataPath('apfs_encrypted.dmg')
    test_evidence = evidence.RawDisk(source_path=test_path)

    # Test without credentials
    with self.assertRaises(TurbiniaException):
      partitions.Enumerate(test_evidence)

    # Test with bad credentials
    test_evidence.credentials = [('password', 'apfs!TEST')]
    with self.assertRaises(TurbiniaException):
      partitions.Enumerate(test_evidence)

    # Test with good credentials
    test_evidence.credentials = [('password', 'apfs-TEST')]
    path_specs = partitions.Enumerate(test_evidence)
    self.assertEqual(len(path_specs), 1)

  def testEnumerateOnBDE(self):
    """Test Enumerate on BDE."""
    test_path = self._getTestDataPath('bdetogo.raw')
    test_evidence = evidence.RawDisk(source_path=test_path)

    # Test without credentials
    with self.assertRaises(TurbiniaException):
      partitions.Enumerate(test_evidence)

    # Test with bad credentials
    test_evidence.credentials = [('password', 'bde!TEST')]
    with self.assertRaises(TurbiniaException):
      partitions.Enumerate(test_evidence)

    # Test with good credentials
    test_evidence.credentials = [('password', 'bde-TEST')]
    path_specs = partitions.Enumerate(test_evidence)
    self.assertEqual(len(path_specs), 2)

    # Test GetPartitionEncryptionType
    encryption_type = partitions.GetPartitionEncryptionType(path_specs[0])
    self.assertEqual(encryption_type, 'BDE')

  def testEnumerateOnGPTImage(self):
    """Test Enumerate on GPT image."""
    test_path = self._getTestDataPath('gpt.raw')
    test_evidence = evidence.RawDisk(source_path=test_path)
    path_specs = partitions.Enumerate(test_evidence)
    self.assertEqual(len(path_specs), 2)

  def testEnumerateOnLVM(self):
    """Test Enumerate on LVM image."""
    test_path = self._getTestDataPath('lvm.raw')
    test_evidence = evidence.RawDisk(source_path=test_path)
    path_specs = partitions.Enumerate(test_evidence)
    self.assertEqual(len(path_specs), 1)

  def testEnumerateOnPartitionedImage(self):
    """Test Enumerate on partitioned image."""
    test_path = self._getTestDataPath('mbr.raw')
    test_evidence = evidence.RawDisk(source_path=test_path)
    path_specs = partitions.Enumerate(test_evidence)
    self.assertEqual(len(path_specs), 2)

    # Test GetPathSpecByLocation
    path_spec = partitions.GetPathSpecByLocation(path_specs, '/p1')
    self.assertIsNotNone(path_spec)

  def testEnumerateOnRaw(self):
    """Test Enumerate on raw image."""
    test_path = self._getTestDataPath('ext2.raw')
    test_evidence = evidence.RawDisk(source_path=test_path)
    path_specs = partitions.Enumerate(test_evidence)
    self.assertEqual(len(path_specs), 1)
