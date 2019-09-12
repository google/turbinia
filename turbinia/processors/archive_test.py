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

from random import randint
from shutil import rmtree
from turbinia.processors import archive
from turbinia import TurbiniaException


class ArchiveProcessorTest(unittest.TestCase):
  """Tests for Archive Processor."""
  filedir = os.path.dirname(os.path.realpath(__file__))
  testdir = os.path.join(filedir, '..', '..', 'test_data', "archive_test")
  testfiles = os.path.join(testdir, 'files')
  testarchive = os.path.join(testdir, 'files.tar.gz')

  def setUp(self):
    # Setup testing directories.
    if not os.path.exists(self.testdir):
      os.makedirs(self.testdir)
    if not os.path.exists(self.testfiles):
      os.makedirs(self.testfiles)
    archive.CompressFolder(self.testfiles)

    # Generate text files containing random numbers.
    file_max = 10
    counter = 0
    while counter <= file_max:
      file_name = os.path.join(
          self.testfiles, 'file{0:s}.txt'.format(str(counter)))
      file_open = open(file_name, 'w+')
      rand_nums = [randint(0, 1000) for i in range(50)]
      for i in rand_nums:
        file_open.write('%s\n' % str(i))
      file_open.close()
      counter += 1

  def tearDown(self):
    # Remove testing directory for this unit test.
    if os.path.exists(self.testdir):
      rmtree(self.testdir)

  def test_compressed_dir(self):
    """Tests the compression function"""
    # Check if compressed directory matches expected output path.
    self.assertEqual(archive.CompressFolder(self.testfiles), self.testarchive)

    # Check to confirm that the archive is gzip format.
    self.assertEqual(tarfile.is_tarfile(self.testarchive), True)

    # Raise assertion if folder does not exist.
    with self.assertRaises(TurbiniaException):
      archive.CompressFolder('blah')

  def test_uncompressed_dir(self):
    """Tests the decompression function"""
    # Check to confirm that the decompressed directory matches
    # the expected output path.
    self.assertEqual(
        archive.DecompressArchive(self.testarchive), self.testfiles)


if __name__ == '__main__':
  unittest.main()
