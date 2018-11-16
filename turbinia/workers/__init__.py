# -*- coding: utf-8 -*-
# Copyright 2018 Google Inc.
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
"""Turbinia task."""

from __future__ import unicode_literals

from datetime import datetime
import getpass
import logging
import os
import pickle
import platform
import pprint
import subprocess
import traceback
import uuid

import filelock

from turbinia import config
from turbinia import output_manager
from turbinia import TurbiniaException

log = logging.getLogger('turbinia')


class TurbiniaTaskResult(object):
  """Object to store task results to be returned by a TurbiniaTask.

  Attributes:
      base_output_dir: Base path for local output
      closed: Boolean indicating whether this result is closed
      output_dir: Full path for local output
      error: Dict of error data ('error' and 'traceback' are some valid keys)
      evidence: List of newly created Evidence objects.
      id: Unique Id of result (string of hex)
      input_evidence: The evidence this task processed.
      request_id: The id of the initial request to process this evidence.
      run_time: Length of time the task ran for.
      saved_paths: Paths where output has been saved.
      start_time: Datetime object of when the task was started
      status: A one line descriptive task status.
      successful: Bool indicating success status.
      task_id: Task ID of the parent task.
      task_name: Name of parent task.
      user: The user who requested the task.
      worker_name: Name of worker task executed on.
      _log: A list of log messages
  """

  # The list of attributes that we will persist into storage
  STORED_ATTRIBUTES = ['worker_name', 'status', 'saved_paths', 'successful']

  def __init__(
      self, task, evidence=None, input_evidence=None, base_output_dir=None,
      request_id=None):
    """Initialize the TurbiniaTaskResult object.

    Args:
      task (TurbiniaTask): The calling Task object

    Raises:
      TurbiniaException: If the Output Manager is not setup.
    """

    self.closed = False
    self.evidence = evidence if evidence else []
    self.input_evidence = input_evidence if input_evidence else []
    self.id = uuid.uuid4().hex
    self.task_id = task.id
    self.task_name = task.name
    self.base_output_dir = base_output_dir
    self.request_id = request_id
    self.user = task.user

    self.start_time = datetime.now()
    self.run_time = None
    self.saved_paths = []
    self.successful = None
    self.status = None
    self.error = {}
    self.worker_name = platform.node()
    # TODO(aarontp): Create mechanism to grab actual python logging data.
    self._log = []
    if task.output_manager.is_setup:
      _, self.output_dir = task.output_manager.get_local_output_dirs()
    else:
      raise TurbiniaException('Output Manager is not setup yet.')

  def __str__(self):
    return pprint.pformat(vars(self), depth=3)

  def close(self, task, success, status=None):
    """Handles closing of this result and writing logs.

    Normally this should be called by the Run method to make sure that the
    status, etc are set correctly, but if there is an exception thrown when the
    task executes, then run_wrapper will call this with default arguments
    indicating a failure.

    Args:
      task (TurbiniaTask): The calling Task object
      success: Bool indicating task success
      status: One line descriptive task status.
    """
    if self.closed:
      # Don't try to close twice.
      return
    self.successful = success
    self.run_time = datetime.now() - self.start_time
    if not status:
      status = 'Completed successfully in {0:s} on {1:s}'.format(
          str(self.run_time), self.worker_name)
    self.log(status)
    self.status = status

    for evidence in self.evidence:
      if evidence.local_path:
        self.saved_paths.append(evidence.local_path)
        if not task.run_local:
          if evidence.copyable and not config.SHARED_FILESYSTEM:
            task.output_manager.save_evidence(evidence, self)
      if not evidence.request_id:
        evidence.request_id = self.request_id

    for evidence in self.input_evidence:
      try:
        evidence.postprocess()
      # Adding a broad exception here because we want to try post-processing
      # to clean things up even after other failures in the task, so this could
      # also fail.
      # pylint: disable=broad-except
      except Exception as e:
        msg = 'Evidence post-processing for {0:s} failed: {1!s}'.format(
            evidence.name, e)
        log.error(msg)
        self.log(msg)

    # Write result log info to file
    logfile = os.path.join(self.output_dir, 'worker-log.txt')
    if self.output_dir and os.path.exists(self.output_dir):
      with open(logfile, 'w') as f:
        f.write('\n'.join(self._log))
        f.write('\n')
      if not task.run_local:
        task.output_manager.save_local_file(logfile, self)

    self.closed = True
    log.debug('Result close successful. Status is [{0:s}]'.format(self.status))

  def log(self, log_msg):
    """Add a log message to the result object.

    Args:
      log_msg: A log message string.
    """
    log.info(log_msg)
    self._log.append(log_msg)

  def add_evidence(self, evidence, evidence_config):
    """Populate the results list.

    Args:
        evidence: Evidence object
        evidence_config (dict): The evidence config we want to associate with
            this object.  This will be passed in with the original evidence that
            was supplied to the task, so likely the caller will always want to
            use evidence_.config for this parameter.
    """
    # We want to enforce this here to make sure that any new Evidence objects
    # created also contain the config.  We could create a closure to do this
    # automatically, but the real fix is to attach this to a separate object.
    # See https://github.com/google/turbinia/issues/211 for more details.
    evidence.config = evidence_config

    self.evidence.append(evidence)

  def set_error(self, error, traceback_):
    """Add error and traceback.

    Args:
        error: Short string describing the error.
        traceback_: Traceback of the error.
    """
    self.error['error'] = error
    self.error['traceback'] = traceback_


class TurbiniaTask(object):
  """Base class for Turbinia tasks.

  Attributes:
      base_output_dir: The base directory that output will go into.  Per-task
                       directories will be created under this.
      id: Unique Id of task (string of hex)
      last_update: A datetime object with the last time the task was updated.
      name: Name of task
      output_dir: The directory output will go into (including per-task folder).
      output_manager: An output manager object
      result: A TurbiniaTaskResult object.
      request_id: The id of the initial request to process this evidence.
      run_local: Whether we are running locally without a Worker or not.
      state_key: A key used to manage task state
      stub: The task manager implementation specific task stub that exists
            server side to keep a reference to the remote task objects.  For PSQ
            this is a task result object, but other implementations have their
            own stub objects.
      tmp_dir: Temporary directory for Task to write to.
      user: The user who requested the task.
      _evidence_config (dict): The config that we want to pass to all new
            evidence created from this task.
  """

  # The list of attributes that we will persist into storage
  STORED_ATTRIBUTES = ['id', 'last_update', 'name', 'request_id', 'user']

  def __init__(
      self, name=None, base_output_dir=None, request_id=None, user=None):
    """Initialization for TurbiniaTask."""
    if base_output_dir:
      self.base_output_dir = base_output_dir
    else:
      self.base_output_dir = config.OUTPUT_DIR
    self.id = uuid.uuid4().hex
    self.last_update = datetime.now()
    self.name = name if name else self.__class__.__name__
    self.output_dir = None
    self.output_manager = output_manager.OutputManager()
    self.result = None
    self.request_id = request_id
    self.run_local = False
    self.state_key = None
    self.stub = None
    self.tmp_dir = None
    self.user = user if user else getpass.getuser()
    self._evidence_config = {}

  def execute(
      self, cmd, result, save_files=None, new_evidence=None, close=False,
      shell=False):
    """Executes a given binary and saves output.

    Args:
      cmd (list|string): Command arguments to run
      result (TurbiniaTaskResult): The result object to put data into.
      save_files (list): A list of files to save (files referenced by Evidence
          objects are automatically saved, so no need to include them).
      new_evidence (list): These are new evidence objects created by the task.
          If the task is successful, they will be added to the result.
      close (bool): Whether to close out the result.
      shell (bool): Whether the cmd is in the form of a string or a list.

    Returns:
      Tuple of the return code, and the TurbiniaTaskResult object
    """
    save_files = save_files if save_files else []
    new_evidence = new_evidence if new_evidence else []
    if shell:
      proc = subprocess.Popen(cmd, shell=True)
    else:
      proc = subprocess.Popen(cmd)
    stdout, stderr = proc.communicate()
    result.error['stdout'] = stdout
    result.error['stderr'] = stderr
    ret = proc.returncode

    if ret:
      msg = 'Execution failed with status {0:d}'.format(ret)
      result.log(msg)
      if close:
        result.close(self, success=False, status=msg)
    else:
      for file_ in save_files:
        result.log('Output file at {0:s}'.format(file_))
        if not self.run_local:
          self.output_manager.save_local_file(file_, result)
      for evidence in new_evidence:
        # If the local path is set in the Evidence, we check to make sure that
        # the path exists and is not empty before adding it.
        if evidence.local_path and not os.path.exists(evidence.local_path):
          msg = (
              'Evidence {0:s} local_path {1:s} does not exist. Not returning '
              'empty Evidence.'.format(evidence.name, evidence.local_path))
          result.log(msg)
          log.warning(msg)
        elif (evidence.local_path and os.path.exists(evidence.local_path) and
              os.path.getsize(evidence.local_path) == 0):
          msg = (
              'Evidence {0:s} local_path {1:s} is empty. Not returning '
              'empty new Evidence.'.format(evidence.name, evidence.local_path))
          result.log(msg)
          log.warning(msg)
        else:
          new_path, _ = self.output_manager.save_local_file(
              evidence.local_path, result)
          if new_path:
            evidence.local_path = new_path
          result.add_evidence(evidence, self._evidence_config)

      if close:
        result.close(self, success=True)

    return ret, result

  def setup(self, evidence):
    """Perform common setup operations and runtime environment.

    Even though TurbiniaTasks are initially instantiated by the Jobs under the
    Task Manager, this setup method needs to be run from the task on the worker
    because it handles setting up the task runtime environment.

    Args:
      evidence: An Evidence object to process.

    Returns:
      A TurbiniaTaskResult object.

    Raises:
      TurbiniaException: If the evidence can not be found.
    """
    self.output_manager.setup(self)
    self.tmp_dir, self.output_dir = self.output_manager.get_local_output_dirs()
    if not self.result:
      self.result = TurbiniaTaskResult(
          task=self, input_evidence=[evidence],
          base_output_dir=self.base_output_dir, request_id=self.request_id)

    if not self.run_local:
      if evidence.copyable and not config.SHARED_FILESYSTEM:
        self.output_manager.retrieve_evidence(evidence)

    if evidence.local_path and not os.path.exists(evidence.local_path):
      raise TurbiniaException(
          'Evidence local path {0:s} does not exist'.format(
              evidence.local_path))
    evidence.preprocess()
    return self.result

  def touch(self):
    """Updates the last_update time of the task."""
    self.last_update = datetime.now()

  def validate_result(self, result):
    """Checks to make sure that the result is valid.

    We occasionally get something added into a TurbiniaTaskResult that makes
    it unpickleable.  We don't necessarily know what caused it to be in that
    state, so we need to create a new, mostly empty result so that the client
    is able to get the error message (otherwise the task will stay pending
    indefinitely).

    Args:
      result (TurbiniaTaskResult): Result object to check

    Returns:
      The original result object if it is OK, otherwise an empty result object
      indicating a failure.
    """
    bad_message = None
    check_status = 'Successful'

    if not isinstance(result, TurbiniaTaskResult):
      bad_message = (
          'Task returned type [{0!s}] instead of TurbiniaTaskResult.').format(
              type(result))
    else:
      try:
        log.debug('Checking TurbiniaTaskResult for serializability')
        pickle.dumps(result)
      except (TypeError, pickle.PicklingError) as e:
        bad_message = (
            'Error pickling TurbiniaTaskResult object. Returning a new result '
            'with the pickling error, and all previous result data will be '
            'lost. Pickle Error: {0!s}'.format(e))

    if bad_message:
      log.error(bad_message)
      if result and hasattr(result, 'status') and result.status:
        old_status = result.status
      else:
        old_status = 'No previous status'

      result = TurbiniaTaskResult(
          task=self, base_output_dir=self.base_output_dir,
          request_id=self.request_id)
      result.status = '{0:s}. Previous status: [{1:s}]'.format(
          bad_message, old_status)
      result.set_error(bad_message, traceback.format_exc())
      result.close(self, success=False, status=bad_message)
      check_status = 'Failed, but replaced with empty result'

    log.info('Result check: {0:s}'.format(check_status))
    return result

  def run_wrapper(self, evidence):
    """Wrapper to manage TurbiniaTaskResults and exception handling.

    This wrapper should be called to invoke the run() methods so it can handle
    the management of TurbiniaTaskResults and the exception handling.  Otherwise
    details from exceptions in the worker cannot be propagated back to the
    Turbinia TaskManager.

    This method should handle (in no particular order):
      - Exceptions thrown from run()
      - Verifing valid TurbiniaTaskResult object is returned
          - Check for bad results (non TurbiniaTaskResults) returned from run()
          - Auto-close results that haven't been closed
          - Verifying that the results are serializeable
      - Locking to make sure only one task is active at a time

    Args:
      evidence: Evidence object

    Returns:
      A TurbiniaTaskResult object
    """
    with filelock.FileLock(config.LOCK_FILE):
      log.info('Starting Task {0:s} {1:s}'.format(self.name, self.id))
      original_result_id = None
      try:
        self.result = self.setup(evidence)
        original_result_id = self.result.id
        self._evidence_config = evidence.config
        self.result = self.run(evidence, self.result)
      # pylint: disable=broad-except
      except Exception as e:
        msg = '{0:s} Task failed with exception: [{1!s}]'.format(self.name, e)
        log.error(msg)
        log.error(traceback.format_exc())
        if self.result:
          self.result.log(msg)
          self.result.log(traceback.format_exc())
          if hasattr(e, 'message'):
            self.result.set_error(e.message, traceback.format_exc())
          else:
            self.result.set_error(e.__class__, traceback.format_exc())
          self.result.status = msg
        else:
          log.error('No TurbiniaTaskResult object found after task execution.')

      self.result = self.validate_result(self.result)

      # Trying to close the result if possible so that we clean up what we can.
      # This has a higher likelihood of failing because something must have gone
      # wrong as the Task should have already closed this.
      if self.result and not self.result.closed:
        msg = 'Trying last ditch attempt to close result'
        log.warning(msg)
        self.result.log(msg)

        if self.result.status:
          status = self.result.status
        else:
          status = 'No previous status'
        msg = (
            'Task Result was auto-closed from task executor on {0:s} likely '
            'due to previous failures.  Previous status: [{1:s}]'.format(
                self.result.worker_name, status))
        self.result.log(msg)
        try:
          self.result.close(self, False, msg)
        # Using broad except here because lots can go wrong due to the reasons
        # listed above.
        # pylint: disable=broad-except
        except Exception as e:
          log.error('TurbiniaTaskResult close failed: {0!s}'.format(e))
          if not self.result.status:
            self.result.status = msg
        # Check the result again after closing to make sure it's still good.
        self.result = self.validate_result(self.result)

    if original_result_id != self.result.id:
      log.debug(
          'Result object {0:s} is different from original {1!s} after task '
          'execution which indicates errors during execution'.format(
              self.result.id, original_result_id))
    else:
      log.debug(
          'Returning original result object {0:s} after task execution'.format(
              self.result.id))
    # TODO(aarontp): Find a better way to ensure this gets unset.
    self.output_manager = None
    return self.result

  def run(self, evidence, result):
    """Entry point to execute the task.

    Args:
      evidence: Evidence object.
      result: A TurbiniaTaskResult object to place task results into.

    Returns:
        TurbiniaTaskResult object.
    """
    raise NotImplementedError
