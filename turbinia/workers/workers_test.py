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
import os
import tempfile
import unittest
import mock

from turbinia import evidence
from turbinia import TurbiniaException
from turbinia.workers import TurbiniaTask
from turbinia.workers import TurbiniaTaskResult
from turbinia.workers.plaso import PlasoTask
from turbinia import state_manager


class TestTurbiniaTaskBase(unittest.TestCase):
  """Test TurbiniaTask class.

  Attributes:
    class_task(TurbiniaTask): The class the test should instantiated
    remove_file(list(str)): Files that will be removed after the test run
    remove_dirs(list(str)): Dirs that will be removed after the test run
    base_output_dir(str): The base output directory used by the Task
    task(TurbiniaTask): The instantiated Task under test
    evidence(Evidence): The test evidence object used by the Task
    result(TurbiniaResult): The result object used by the Task
  """

  def setUp(self, task_class=TurbiniaTask, evidence_class=evidence.RawDisk):
    self.task_class = task_class
    self.evidence_class = evidence_class
    self.remove_files = []
    self.remove_dirs = []

    # Set up Tasks under test
    self.base_output_dir = tempfile.mkdtemp()
    self.plaso_task = PlasoTask(base_output_dir=self.base_output_dir)
    self.plaso_task.output_manager = mock.MagicMock()
    self.plaso_task.output_manager.get_local_output_dirs.return_value = (
        None, None)
    self.task = self.task_class(base_output_dir=self.base_output_dir)
    self.task.job_name = 'PlasoJob'
    self.task.output_manager = mock.MagicMock()
    self.task.output_manager.get_local_output_dirs.return_value = (None, None)

    # Set up RawDisk Evidence
    test_disk_path = tempfile.mkstemp(dir=self.base_output_dir)[1]
    self.remove_files.append(test_disk_path)
    self.evidence = evidence.RawDisk(source_path=test_disk_path)
    self.evidence.preprocess = mock.MagicMock()
    # Set up TurbiniaTaskResult
    self.result = TurbiniaTaskResult(base_output_dir=self.base_output_dir)

    self.result.output_dir = self.base_output_dir

  def tearDown(self):
    for remove_file in self.remove_files:
      if os.path.exists(remove_file):
        os.remove(remove_file)

    for directory in self.remove_dirs:
      if os.path.exists(directory):
        os.rmdir(directory)

    os.rmdir(self.base_output_dir)

  def setResults(
      self, setup=None, run=None, validate_result=None, mock_run=True):
    """Set up mock returns in TurbiniaTaskResult object.

    Args:
      setup: What value to return from setup()
      run: What value to return from run()
      validate_result: What value to return from validate_result()
      mock_run(bool): Whether to mock out the run method
    """
    if setup is None:
      setup = self.result
    if run is None:
      run = self.result
    if validate_result is None:
      validate_result = self.result

    self.result.status = 'TestStatus'
    self.result.update_task_status = mock.MagicMock()
    self.result.close = mock.MagicMock()
    self.task.setup = mock.MagicMock(return_value=setup)
    self.result.worker_name = 'worker1'
    self.result.state_manager = None
    if mock_run:
      self.task.run = mock.MagicMock(return_value=run)
    self.task.validate_result = mock.MagicMock(return_value=validate_result)


class TestTurbiniaTask(TestTurbiniaTaskBase):
  """Test TurbiniaTask class."""

  def testTurbiniaTaskSerialize(self):
    """Test that we can properly serialize/deserialize tasks."""
    out_dict = self.plaso_task.serialize()
    out_obj = TurbiniaTask.deserialize(out_dict)
    self.assertIsInstance(out_obj, PlasoTask)
    # Nuke output_manager so we don't deal with class equality
    self.plaso_task.output_manager = None
    out_obj.output_manager = None
    self.assertEqual(out_obj.__dict__, self.plaso_task.__dict__)

  def testTurbiniaTaskRunWrapper(self):
    """Test that the run wrapper executes task run."""
    self.setResults()
    self.result.closed = True
    new_result = self.task.run_wrapper(self.evidence.__dict__)

    new_result = TurbiniaTaskResult.deserialize(new_result)
    self.assertEqual(new_result.status, 'TestStatus')
    self.result.close.assert_not_called()

  def testTurbiniaTaskRunWrapperAutoClose(self):
    """Test that the run wrapper closes the task."""
    self.setResults()
    new_result = self.task.run_wrapper(self.evidence.__dict__)
    new_result = TurbiniaTaskResult.deserialize(new_result)
    self.assertEqual(new_result.status, 'TestStatus')
    self.result.close.assert_called()

  @mock.patch('turbinia.state_manager.get_state_manager')
  def testTurbiniaTaskRunWrapperBadResult(self, _):
    """Test that the run wrapper recovers from run returning bad result."""
    bad_result = 'Not a TurbiniaTaskResult'
    checked_result = TurbiniaTaskResult(base_output_dir=self.base_output_dir)
    checked_result.setup(self.task)
    checked_result.status = 'CheckedResult'
    self.setResults(run=bad_result, validate_result=checked_result)
    new_result = self.task.run_wrapper(self.evidence.__dict__)
    new_result = TurbiniaTaskResult.deserialize(new_result)
    self.task.validate_result.assert_any_call(bad_result)
    self.assertEqual(type(new_result), TurbiniaTaskResult)
    self.assertIn('CheckedResult', new_result.status)

  def testTurbiniaTaskJobUnavailable(self):
    """Test that the run wrapper can fail if the job doesn't exist."""
    self.setResults()
    self.task.job_name = 'non_exist'
    canary_status = (
        'Task will not run due to the job: '
        'non_exist being disabled on the worker.')
    new_result = self.task.run_wrapper(self.evidence.__dict__)
    new_result = TurbiniaTaskResult.deserialize(new_result)
    self.assertEqual(new_result.status, canary_status)

  def testTurbiniaTaskRunWrapperExceptionThrown(self):
    """Test that the run wrapper recovers from run throwing an exception."""
    self.setResults()
    self.task.run = mock.MagicMock(side_effect=TurbiniaException)

    new_result = self.task.run_wrapper(self.evidence.__dict__)
    new_result = TurbiniaTaskResult.deserialize(new_result)
    self.assertEqual(type(new_result), TurbiniaTaskResult)
    self.assertIn('failed', new_result.status)

  @mock.patch('turbinia.state_manager.get_state_manager')
  def testTurbiniaTaskRunWrapperSetupFail(self, _):
    """Test that the run wrapper recovers from setup failing."""
    self.task.result = None
    canary_status = 'exception_message'
    self.task.setup = mock.MagicMock(
        side_effect=TurbiniaException('exception_message'))
    self.remove_files.append(
        os.path.join(self.task.base_output_dir, 'worker-log.txt'))

    new_result = self.task.run_wrapper(self.evidence.__dict__)
    new_result = TurbiniaTaskResult.deserialize(new_result)
    self.assertEqual(type(new_result), TurbiniaTaskResult)
    self.assertIn(canary_status, new_result.status)

  def testTurbiniaTaskValidateResultGoodResult(self):
    """Tests validate_result with good result."""
    self.result.status = 'GoodStatus'
    self.result.state_manager = None
    new_result = self.task.validate_result(self.result)
    self.assertEqual(new_result.status, 'GoodStatus')
    self.assertDictEqual(new_result.error, {})

  @mock.patch('turbinia.workers.TurbiniaTaskResult.close')
  @mock.patch('turbinia.state_manager.get_state_manager')
  def testTurbiniaTaskValidateResultBadResult(self, _, __):
    """Tests validate_result with bad result."""
    # Passing in an unpickleable object (json module) and getting back a
    # TurbiniaTaskResult
    new_result = self.task.validate_result(json)
    self.assertEqual(type(new_result), TurbiniaTaskResult)
    self.assertNotEqual(new_result.error, {})

  @mock.patch('turbinia.workers.evidence_decode')
  def testTurbiniaTaskEvidenceValidationFailure(self, evidence_decode_mock):
    """Tests Task fails when evidence validation fails."""
    self.setResults()
    test_evidence = evidence.RawDisk()
    test_evidence.REQUIRED_ATTRIBUTES = ['doesnotexist']
    evidence_decode_mock.return_value = test_evidence
    test_result = self.task.run_wrapper(test_evidence.__dict__)
    test_result = TurbiniaTaskResult.deserialize(test_result)
    self.assertFalse(test_result.successful)
    self.assertIn('validation failed', test_result.status)

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
    """Test execution with new evidence that has valid a source_path."""
    cmd = 'test cmd'
    output = ('test stdout', 'test stderr')

    self.result.close = mock.MagicMock()
    proc_mock = mock.MagicMock()
    proc_mock.communicate.return_value = output
    proc_mock.returncode = 0
    popen_mock.return_value = proc_mock

    # Create our evidence local path file
    with open(self.evidence.source_path, 'w') as evidence_path:
      evidence_path.write('test')

    self.task.execute(
        cmd, self.result, new_evidence=[self.evidence], close=True)
    self.assertIn(self.evidence, self.result.evidence)

  @mock.patch('turbinia.workers.subprocess.Popen')
  def testTurbiniaTaskExecuteEvidenceDoesNotExist(self, popen_mock):
    """Test execution with new evidence that does not have a source_path."""
    cmd = 'test cmd'
    output = ('test stdout', 'test stderr')

    self.result.close = mock.MagicMock()
    proc_mock = mock.MagicMock()
    proc_mock.communicate.return_value = output
    proc_mock.returncode = 0
    popen_mock.return_value = proc_mock

    self.task.execute(
        cmd, self.result, new_evidence=[self.evidence], close=True)
    self.assertNotIn(self.evidence, self.result.evidence)

  @mock.patch('turbinia.workers.subprocess.Popen')
  def testTurbiniaTaskExecuteEvidenceExistsButEmpty(self, popen_mock):
    """Test execution with new evidence source_path that exists but is empty."""
    cmd = 'test cmd'
    output = ('test stdout', 'test stderr')

    self.result.close = mock.MagicMock()
    proc_mock = mock.MagicMock()
    proc_mock.communicate.return_value = output
    proc_mock.returncode = 0
    popen_mock.return_value = proc_mock

    # Exists and is empty
    self.assertTrue(os.path.exists(self.evidence.source_path))
    self.assertEqual(os.path.getsize(self.evidence.source_path), 0)

    self.task.execute(
        cmd, self.result, new_evidence=[self.evidence], close=True)
    self.assertNotIn(self.evidence, self.result.evidence)

  def testEvidenceSetup(self):
    """Tests basic run of evidence_setup."""
    self.evidence.preprocess = mock.MagicMock()
    self.task.evidence_setup(self.evidence)
    self.evidence.preprocess.assert_called_with(
        self.task.tmp_dir, required_states=self.task.REQUIRED_STATES)

  def testEvidenceSetupStateNotFulfilled(self):
    """Test that evidence setup throws exception when states don't match."""
    self.evidence.preprocess = mock.MagicMock()
    self.evidence.POSSIBLE_STATES = [evidence.EvidenceState.ATTACHED]
    self.task.REQUIRED_STATES = [evidence.EvidenceState.ATTACHED]

    # The current state of the evience as shown in evidence.state[ATTACHED] is
    # not True, so this should throw an exception
    self.assertRaises(
        TurbiniaException, self.task.evidence_setup, self.evidence)

    # Runs fine after setting the state
    self.evidence.state[evidence.EvidenceState.ATTACHED] = True
    self.task.evidence_setup(self.evidence)
