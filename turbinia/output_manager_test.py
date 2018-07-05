# -*- coding: utf-8 -*-
# Copyright 2016 Google Inc.
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
"""Tests for Turbinia OutputWriters."""

from __future__ import unicode_literals

import unittest
import os
import tempfile

from turbinia import output_manager


class TestLocalOutputWriter(unittest.TestCase):
  """Test LocalOutputWriter module."""

  def setUp(self):
    self.base_output_dir = tempfile.mkdtemp()
    self.remove_files = []
    self.remove_dirs = []

  def tearDown(self):
    [os.remove(f) for f in self.remove_files]
    [os.rmdir(d) for d in self.remove_dirs]
    os.rmdir(self.base_output_dir)

  def testCreateOutput(self):
    """Test that output directories are created."""
    writer = output_manager.LocalOutputWriter(
        base_output_dir=self.base_output_dir, unique_dir='unique_dir')
    output_dir = writer.create_output_dir()
    self.remove_dirs.append(output_dir)
    self.assertTrue(os.path.exists(output_dir))
    self.assertTrue('unique_dir' in output_dir)

  def testWrite(self):
    """Test that file contents are written."""
    contents = 'test contents'
    test_file = 'test.txt'
    writer = output_manager.LocalOutputWriter(
        base_output_dir=self.base_output_dir, unique_dir='unique_dir')
    output_dir = writer.create_output_dir()
    self.remove_dirs.append(output_dir)
    src = os.path.join(self.base_output_dir, test_file)
    dst = os.path.join(output_dir, test_file)
    self.remove_files.append(src)
    self.remove_files.append(dst)
    with open(src, 'w') as file_handle:
      file_handle.write(contents)

    self.assertTrue(writer.copy_to(src))
    self.assertTrue(os.path.exists(dst))
    self.assertEqual(contents, open(dst).read())

  def testNoFileWrite(self):
    """Test that write fails when no source file exists."""
    test_file = 'test.txt'
    writer = output_manager.LocalOutputWriter(
        base_output_dir=self.base_output_dir, unique_dir='unique_dir')
    output_dir = writer.create_output_dir()
    self.remove_dirs.append(output_dir)
    src = os.path.join(self.base_output_dir, test_file)
    dst = os.path.join(output_dir, test_file)

    self.assertFalse(writer.copy_to(src))
    self.assertFalse(os.path.exists(dst))

  def testFileExistsWrite(self):
    """Test that file is not overwritten when it exists."""
    contents = 'test contents'
    other_contents = 'other test contents'
    test_file = 'test.txt'
    writer = output_manager.LocalOutputWriter(
        base_output_dir=self.base_output_dir, unique_dir='unique_dir')
    output_dir = writer.create_output_dir()
    self.remove_dirs.append(output_dir)
    src = os.path.join(self.base_output_dir, test_file)
    dst = os.path.join(output_dir, test_file)
    self.remove_files.append(src)
    self.remove_files.append(dst)

    with open(src, 'w') as file_handle:
      file_handle.write(contents)
    with open(dst, 'w') as file_handle:
      file_handle.write(other_contents)

    self.assertFalse(writer.copy_to(src))
    self.assertEqual(other_contents, open(dst).read())
