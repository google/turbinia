# -*- coding: utf-8 -*-
# Copyright 2019 Google Inc.
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
"""Tests for the Archive processor to compress and decompress folders."""

from __future__ import unicode_literals

import os
import tarfile
import unittest
import tempfile

from random import randint
from shutil import rmtree
from turbinia.processors import archive
from turbinia import TurbiniaException


class ArchiveProcessorTest(unittest.TestCase):
  """Tests for Archive Processor."""

  def setUp(self):
    # Setup testing directories/variables.
    self.test_files = []
    self.base_output_dir = tempfile.mkdtemp(prefix='turbinia-test-local')
    self.tmp_files_dir = os.path.join(self.base_output_dir, 'files')
    self.tmp_archive = os.path.join(self.base_output_dir, 'files.tar.gz')
    if not os.path.exists(self.tmp_files_dir):
      os.makedirs(self.tmp_files_dir)

    # Generate text files containing random numbers.
    file_max = 10
    counter = 0
    while counter <= file_max:
      file_name = 'file{0:s}.txt'.format(str(counter))
      file_path = os.path.join(self.tmp_files_dir, file_name)
      file_open = open(file_path, 'w+')
      rand_nums = [randint(0, 1000) for i in range(50)]
      for i in rand_nums:
        file_open.write('%s\n' % str(i))
      file_open.close()
      counter += 1
      self.test_files.append(file_name)
    archive.CompressDirectory(self.tmp_files_dir)

  def tearDown(self):
    # Remove testing directory for this unit test.
    if os.path.exists(self.base_output_dir):
      rmtree(self.base_output_dir)

  def test_compressed_dir(self):
    """Tests the compression function"""
    # Check if compressed directory matches expected output path.
    self.assertEqual(
        archive.CompressDirectory(self.tmp_files_dir), self.tmp_archive)

    # Check to confirm that the archive is gzip format.
    self.assertEqual(tarfile.is_tarfile(self.tmp_archive), True)

    # Raise assertion if folder does not exist.
    with self.assertRaises(TurbiniaException):
      archive.CompressDirectory('blah')

  def test_validate_tarfile(self):
    """Tests the validate function used to decompress tar files"""

    # Raise exception for file that does not exist.
    with self.assertRaises(TurbiniaException):
      archive.ValidateTarFile('blah.no')

    # Raise exception for a file with unsupported extension.
    with self.assertRaises(TurbiniaException):
      archive.ValidateTarFile(self.tmp_files_dir)


if __name__ == '__main__':
  unittest.main()
