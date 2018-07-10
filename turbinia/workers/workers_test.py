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
"""Tests for workers __init__."""

from __future__ import unicode_literals

import json
import mock
import os
import tempfile
import unittest

from turbinia import evidence
from turbinia import TurbiniaException
from turbinia.workers import TurbiniaTask
from turbinia.workers import TurbiniaTaskResult


class TestTurbiniaTask(unittest.TestCase):
  """Test TurbiniaTask class."""

  def setUp(self):
    self.remove_files = []
    self.remove_dirs = []

    # Set up TurbiniaTask
    self.base_output_dir = tempfile.mkdtemp()
    self.task = TurbiniaTask(base_output_dir=self.base_output_dir)
    self.task.output_manager = mock.MagicMock()

    # Set up RawDisk Evidence
    test_disk_path = tempfile.mkstemp(dir=self.base_output_dir)[1]
    self.remove_files.append(test_disk_path)
    self.evidence = evidence.RawDisk(local_path=test_disk_path)

    # Set up TurbiniaTaskResult
    self.result = TurbiniaTaskResult(
        task=self.task, base_output_dir=self.base_output_dir)

    self.result.output_dir = self.base_output_dir

  def tearDown(self):
    [os.remove(f) for f in self.remove_files if os.path.exists(f)]
    [os.rmdir(d) for d in self.remove_dirs if os.path.exists(d)]
    os.rmdir(self.base_output_dir)

  @mock.patch('turbinia.workers.subprocess.Popen')
  def testTurbiniaTaskExecute(self, popen_mock):
    """Test execution with success case."""
    cmd = 'test cmd'
    output = ('test stdout', 'test stderr')

    self.result.close = mock.MagicMock()
    proc_mock = mock.MagicMock()
    proc_mock.communicate.return_value = output
    proc_mock.returncode = 0
    popen_mock.return_value = proc_mock

    self.task.execute(cmd, self.result, close=True)

    # Command was executed, has the correct output saved and
    # TurbiniaTaskResult.close() was called with successful status.
    popen_mock.assert_called_with(cmd)
    self.assertEqual(self.result.error['stdout'], output[0])
    self.assertEqual(self.result.error['stderr'], output[1])
    self.result.close.assert_called_with(self.task, success=True)

  @mock.patch('turbinia.workers.subprocess.Popen')
  def testTurbiniaTaskExecuteFailure(self, popen_mock):
    """Test execution with failure case."""
    cmd = 'test cmd'
    output = ('test stdout', 'test stderr')

    self.result.close = mock.MagicMock()
    proc_mock = mock.MagicMock()
    proc_mock.communicate.return_value = output
    proc_mock.returncode = 1
    popen_mock.return_value = proc_mock

    self.task.execute(cmd, self.result, close=True)

    # Command was executed and TurbiniaTaskResult.close() was called with
    # unsuccessful status.
    popen_mock.assert_called_with(cmd)
    self.result.close.assert_called_with(
        self.task, success=False, status=mock.ANY)

  @mock.patch('turbinia.workers.subprocess.Popen')
  def testTurbiniaTaskExecuteEvidenceExists(self, popen_mock):
    """Test execution with new evidence that has valid a local_path."""
    cmd = 'test cmd'
    output = ('test stdout', 'test stderr')

    self.result.close = mock.MagicMock()
    proc_mock = mock.MagicMock()
    proc_mock.communicate.return_value = output
    proc_mock.returncode = 0
    popen_mock.return_value = proc_mock

    # Create our evidence local path file
    with open(self.evidence.local_path, 'w') as evidence_path:
      evidence_path.write('test')

    self.task.execute(cmd, self.result, new_evidence=[self.evidence],
                      close=True)
    self.assertIn(self.evidence, self.result.evidence)

  @mock.patch('turbinia.workers.subprocess.Popen')
  def testTurbiniaTaskExecuteEvidenceDoesNotExist(self, popen_mock):
    """Test execution with new evidence that does not have a local_path."""
    cmd = 'test cmd'
    output = ('test stdout', 'test stderr')

    self.result.close = mock.MagicMock()
    proc_mock = mock.MagicMock()
    proc_mock.communicate.return_value = output
    proc_mock.returncode = 0
    popen_mock.return_value = proc_mock

    os.remove(self.evidence.local_path)

    self.task.execute(cmd, self.result, new_evidence=[self.evidence],
                      close=True)
    self.assertNotIn(self.evidence, self.result.evidence)

  @mock.patch('turbinia.workers.subprocess.Popen')
  def testTurbiniaTaskExecuteEvidenceExistsButEmpty(self, popen_mock):
    """Test execution with new evidence local_path that exists but is empty."""
    cmd = 'test cmd'
    output = ('test stdout', 'test stderr')

    self.result.close = mock.MagicMock()
    proc_mock = mock.MagicMock()
    proc_mock.communicate.return_value = output
    proc_mock.returncode = 0
    popen_mock.return_value = proc_mock

    # Exists and is empty
    self.assertTrue(os.path.exists(self.evidence.local_path))
    self.assertEqual(os.path.getsize(self.evidence.local_path), 0)

    self.task.execute(cmd, self.result, new_evidence=[self.evidence],
                      close=True)
    self.assertNotIn(self.evidence, self.result.evidence)
