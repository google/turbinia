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

import io
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
      file_name = f'file{str(counter):s}.txt'
      file_path = os.path.join(self.tmp_files_dir, file_name)
      file_open = open(file_path, 'w+')
      rand_nums = [randint(0, 1000) for i in range(50)]
      for i in rand_nums:
        file_open.write(f'{str(i)}\n')
      file_open.close()
      counter += 1
      self.test_files.append(file_name)
    archive.CompressDirectory(self.tmp_files_dir)

  def _CreateTarFile(self, members):
    """Create a test tar file with the supplied member definitions."""
    tar_path = os.path.join(
        self.base_output_dir, f'test-{randint(0, 1000000):d}.tar.gz')
    with tarfile.open(tar_path, 'w:gz') as tar:
      for member in members:
        tar_info = tarfile.TarInfo(member['name'])
        if 'type' in member:
          tar_info.type = member['type']
        if 'linkname' in member:
          tar_info.linkname = member['linkname']
        data = member.get('data')
        if data is not None:
          data = data.encode('utf-8')
          tar_info.size = len(data)
          tar.addfile(tar_info, io.BytesIO(data))
        else:
          tar.addfile(tar_info)
    return tar_path

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

  def test_uncompress_tarfile(self):
    """Tests that valid tar files are decompressed."""
    tar_path = self._CreateTarFile([{'name': 'safe.txt', 'data': 'safe file'}])

    output_dir = archive.UncompressTarFile(tar_path, self.base_output_dir)

    self.assertTrue(os.path.exists(os.path.join(output_dir, 'safe.txt')))

  def test_uncompress_tarfile_rejects_parent_path(self):
    """Tests that parent directory traversal members are rejected."""
    tar_path = self._CreateTarFile([
        {
            'name': 'safe.txt',
            'data': 'safe file'
        },
        {
            'name': '../escape.txt',
            'data': 'escaped file'
        },
    ])

    with self.assertRaises(TurbiniaException):
      archive.UncompressTarFile(tar_path, self.base_output_dir)

    self.assertFalse(
        os.path.exists(os.path.join(self.base_output_dir, 'escape.txt')))

  def test_uncompress_tarfile_rejects_absolute_path(self):
    """Tests that absolute path members are rejected."""
    escaped_path = os.path.join(self.base_output_dir, 'absolute-escape.txt')
    tar_path = self._CreateTarFile([{
        'name': escaped_path,
        'data': 'escaped file'
    }])

    with self.assertRaises(TurbiniaException):
      archive.UncompressTarFile(tar_path, self.base_output_dir)

    self.assertFalse(os.path.exists(escaped_path))

  def test_uncompress_tarfile_rejects_symlink_escape(self):
    """Tests that symlinks pointing outside the output directory are rejected."""
    tar_path = self._CreateTarFile([{
        'name': 'escape-link',
        'type': tarfile.SYMTYPE,
        'linkname': '..'
    }])

    with self.assertRaises(TurbiniaException):
      archive.UncompressTarFile(tar_path, self.base_output_dir)

  def test_uncompress_tarfile_rejects_hardlink_escape(self):
    """Tests hardlinks pointing outside the output directory are rejected."""
    tar_path = self._CreateTarFile([{
        'name': 'escape-link',
        'type': tarfile.LNKTYPE,
        'linkname': '../escape.txt'
    }])

    with self.assertRaises(TurbiniaException):
      archive.UncompressTarFile(tar_path, self.base_output_dir)


if __name__ == '__main__':
  unittest.main()
