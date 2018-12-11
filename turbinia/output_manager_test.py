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
import shutil
import tempfile

import mock

from turbinia import config
from turbinia import evidence
from turbinia import output_manager
from turbinia import workers


class TestLocalOutputManager(unittest.TestCase):
  """Test LocalOutputManager module."""

  @classmethod
  def setUpClass(cls):
    """Sets up the TestLocalOoutputManager class."""
    config.LoadConfig()

  def setUp(self):
    """Test setup."""
    # Set up TurbiniaTask
    self.base_output_dir = tempfile.mkdtemp(prefix='turbinia-test-local')
    self.tmp_dir = tempfile.mkdtemp(prefix='turbinia-test-tmp')
    self.gcs_save = config.GCS_OUTPUT_PATH
    self.tmp_dir_save = config.TMP_DIR
    config.GCS_OUTPUT_PATH = 'gs://fake/path'
    config.TMP_DIR = self.tmp_dir
    self.task = workers.TurbiniaTask(base_output_dir=self.base_output_dir)

  def tearDown(self):
    """Tears Down class."""
    config.GCS_OUTPUT_PATH = self.gcs_save
    config.TMP_DIR = self.tmp_dir_save
    if 'turbinia-test-local' in self.base_output_dir:
      shutil.rmtree(self.base_output_dir)
    if 'turbinia-test-tmp' in self.tmp_dir:
      shutil.rmtree(self.tmp_dir)

  def testGetOutputWriters(self):
    """Tests get_output_writers function for valid response."""
    writers = output_manager.OutputManager.get_output_writers(self.task)
    self.assertEquals(len(writers), 2)
    for writer in writers:
      self.assertIsInstance(writer, output_manager.OutputWriter)

  def testGetLocalOutputDirs(self):
    """Tests get_local_output_dirs function for valid response."""
    self.task.output_manager.setup(self.task)
    tmp_dir, local_dir = self.task.output_manager.get_local_output_dirs()

    self.assertTrue(self.task.output_manager.is_setup)
    self.assertTrue(os.path.isdir(tmp_dir))
    self.assertTrue(os.path.isdir(local_dir))
    self.assertTrue(tmp_dir.startswith(self.tmp_dir))
    self.assertTrue(local_dir.startswith(self.base_output_dir))

  def testSaveLocalFile(self):
    """Test the save_local_file method."""
    # Set path to None so we don't try to initialize GCS outout writer.
    config.GCS_OUTPUT_PATH = None
    self.task.output_manager.setup(self.task)
    tmp_dir, local_dir = self.task.output_manager.get_local_output_dirs()
    self.task.result = mock.MagicMock()
    self.task.result.saved_paths = []
    test_contents = 'test_contents'
    test_file = 'test-file.out'
    src_file = os.path.join(tmp_dir, test_file)
    dst_file = os.path.join(local_dir, test_file)

    with open(src_file, 'w') as fh:
      fh.write(test_contents)

    self.assertFalse(os.path.exists(dst_file))
    _, __, local_file = self.task.output_manager.save_local_file(
        src_file, self.task.result)
    self.assertTrue(os.path.exists(dst_file))
    self.assertIn(dst_file, self.task.result.saved_paths)
    self.assertEqual(local_file, dst_file)

  def testSaveEvidence(self):
    """Test the save_evidence method."""
    # Set path to None so we don't try to initialize GCS outout writer.
    config.GCS_OUTPUT_PATH = None
    self.task.output_manager.setup(self.task)
    tmp_dir, local_dir = self.task.output_manager.get_local_output_dirs()
    self.task.result = mock.MagicMock()
    self.task.result.saved_paths = []
    test_contents = 'test_contents'
    test_file = 'test-file.out'
    src_file = os.path.join(tmp_dir, test_file)
    dst_file = os.path.join(local_dir, test_file)
    test_evidence = evidence.Evidence()

    with open(src_file, 'w') as fh:
      fh.write(test_contents)
    test_evidence.local_path = src_file

    self.assertFalse(os.path.exists(dst_file))
    return_evidence = self.task.output_manager.save_evidence(
        test_evidence, self.task.result)
    self.assertTrue(os.path.exists(dst_file))
    self.assertIsInstance(return_evidence, evidence.Evidence)
    self.assertIn(dst_file, return_evidence.saved_path)


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
