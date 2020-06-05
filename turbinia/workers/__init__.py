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

from copy import deepcopy
from datetime import datetime, timedelta
from enum import IntEnum
import getpass
import logging
import os
import pickle
import platform
import pprint
import subprocess
import sys
import traceback
import uuid
import turbinia

import filelock

from turbinia import config
from turbinia.config import DATETIME_FORMAT
from turbinia.evidence import evidence_decode
from turbinia import output_manager
from turbinia import TurbiniaException

log = logging.getLogger('turbinia')


class Priority(IntEnum):
  """Reporting priority enum to store common values.

  Priorities can be anything in the range of 0-100, where 0 is the highest
  priority.
  """
  LOW = 80
  MEDIUM = 50
  HIGH = 20
  CRITICAL = 10


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
      job_id (str): The ID of the Job that generated this Task/TaskResult
      report_data (string): Markdown data that can be used in a Turbinia report.
      report_priority (int): Value between 0-100 (0 is the highest priority) to
          be used to order report sections.
      request_id: The id of the initial request to process this evidence.
      run_time: Length of time the task ran for.
      saved_paths: Paths where output has been saved.
      start_time: Datetime object of when the task was started
      status: A one line descriptive task status.
      successful: Bool indicating success status.
      task_id: Task ID of the parent task.
      task_name: Name of parent task.
      requester: The user who requested the task.
      worker_name: Name of worker task executed on.
      _log: A list of log messages
  """

  # The list of attributes that we will persist into storage
  STORED_ATTRIBUTES = [
      'worker_name', 'report_data', 'report_priority', 'run_time', 'status',
      'saved_paths', 'successful'
  ]

  def __init__(
      self, evidence=None, input_evidence=None, base_output_dir=None,
      request_id=None, job_id=None):
    """Initialize the TurbiniaTaskResult object."""

    self.closed = False
    self.evidence = evidence if evidence else []
    self.input_evidence = input_evidence
    self.id = uuid.uuid4().hex
    self.job_id = job_id
    self.base_output_dir = base_output_dir
    self.request_id = request_id

    self.task_id = None
    self.task_name = None
    self.requester = None
    self.output_dir = None

    self.report_data = None
    self.report_priority = Priority.MEDIUM
    self.start_time = datetime.now()
    self.run_time = None
    self.saved_paths = []
    self.successful = None
    self.status = None
    self.error = {}
    self.worker_name = platform.node()
    # TODO(aarontp): Create mechanism to grab actual python logging data.
    self._log = []

  def __str__(self):
    return pprint.pformat(vars(self), depth=3)

  def setup(self, task):
    """Handles initializing task based attributes, after object creation.

    Args:
      task (TurbiniaTask): The calling Task object

    Raises:
      TurbiniaException: If the Output Manager is not setup.
    """

    self.task_id = task.id
    self.task_name = task.name
    self.requester = task.requester
    if task.output_manager.is_setup:
      _, self.output_dir = task.output_manager.get_local_output_dirs()
    else:
      raise TurbiniaException('Output Manager is not setup yet.')

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
    if not status and self.successful:
      status = 'Completed successfully in {0:s} on {1:s}'.format(
          str(self.run_time), self.worker_name)
    elif not status and not self.successful:
      status = 'Run failed in {0:s} on {1:s}'.format(
          str(self.run_time), self.worker_name)
    self.log(status)
    self.status = status

    for evidence in self.evidence:
      if evidence.local_path and os.path.exists(evidence.local_path):
        self.saved_paths.append(evidence.local_path)
        if not task.run_local:
          if evidence.copyable and not config.SHARED_FILESYSTEM:
            task.output_manager.save_evidence(evidence, self)
      else:
        self.log(
            'Evidence {0!s} has empty or missing file at local_path {1!s} so '
            'not saving.'.format(evidence.name, evidence.local_path))

      if not evidence.request_id:
        evidence.request_id = self.request_id

    try:
      self.input_evidence.postprocess()
    # Adding a broad exception here because we want to try post-processing
    # to clean things up even after other failures in the task, so this could
    # also fail.
    # pylint: disable=broad-except
    except Exception as exception:
      message = 'Evidence post-processing for {0:s} failed: {1!s}'.format(
          self.input_evidence.name, exception)
      self.log(message, level=logging.ERROR)

    # Write result log info to file
    logfile = os.path.join(self.output_dir, 'worker-log.txt')
    # Create default log text just so that the worker log is created to
    # avoid confusion if it doesn't exist.
    if not self._log:
      self._log.append('No worker messages were logged.')
    if self.output_dir and os.path.exists(self.output_dir):
      with open(logfile, 'w') as f:
        f.write('\n'.join(self._log))
        f.write('\n')
      if not task.run_local:
        task.output_manager.save_local_file(logfile, self)

    self.closed = True
    log.debug('Result close successful. Status is [{0:s}]'.format(self.status))

  def log(self, message, level=logging.INFO, traceback_=None):
    """Log Task messages.

    Logs to both the result and the normal logging mechanism.

    Args:
      message (string): Message to log.
      level (int): Log level as defined by logging enums (e.g. logging.INFO)
      traceback (string): Trace message to log
    """
    self._log.append(message)
    if level == logging.DEBUG:
      log.debug(message)
    elif level == logging.INFO:
      log.info(message)
    elif level == logging.WARN:
      log.warn(message)
    elif level == logging.ERROR:
      log.error(message)
    elif level == logging.CRITICAL:
      log.critical(message)

    if traceback_:
      self.result.set_error(message, traceback_)

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
    if evidence.context_dependent:
      evidence.parent_evidence = self.input_evidence

    self.evidence.append(evidence)

  def set_error(self, error, traceback_):
    """Add error and traceback.

    Args:
        error: Short string describing the error.
        traceback_: Traceback of the error.
    """
    self.error['error'] = error
    self.error['traceback'] = traceback_

  def serialize(self):
    """Prepares result object for serialization.

    Returns:
      dict: Object dictionary that is JSON serializable.
    """
    self.run_time = self.run_time.total_seconds() if self.run_time else None
    self.start_time = self.start_time.strftime(DATETIME_FORMAT)
    if self.input_evidence:
      self.input_evidence = self.input_evidence.serialize()
    self.evidence = [x.serialize() for x in self.evidence]
    return self.__dict__

  @classmethod
  def deserialize(cls, input_dict):
    """Converts an input dictionary back into a TurbiniaTaskResult object.

    Args:
      input_dict (dict): TurbiniaTaskResult object dictionary.

    Returns:
      TurbiniaTaskResult: Deserialized object.
    """
    result = TurbiniaTaskResult()
    result.__dict__.update(input_dict)
    if result.run_time:
      result.run_time = timedelta(seconds=result.run_time)
    result.start_time = datetime.strptime(result.start_time, DATETIME_FORMAT)
    if result.input_evidence:
      result.input_evidence = evidence_decode(result.input_evidence)
    result.evidence = [evidence_decode(x) for x in result.evidence]

    return result


class TurbiniaTask(object):
  """Base class for Turbinia tasks.

  Attributes:
      base_output_dir (str): The base directory that output will go into.
          Per-task directories will be created under this.
      id (str): Unique Id of task (string of hex)
      is_finalize_task (bool): Whether this is a finalize Task or not.
      job_id (str): Job ID the Task was created by.
      last_update (datetime): A datetime object with the last time the task was
          updated.
      name (str): Name of task
      output_dir (str): The directory output will go into (including per-task
          folder).
      output_manager (OutputManager): The object that manages saving output.
      result (TurbiniaTaskResult): A TurbiniaTaskResult object.
      request_id (str): The id of the initial request to process this evidence.
      run_local (bool): Whether we are running locally without a Worker or not.
      state_key (str): A key used to manage task state
      stub (psq.task.TaskResult|celery.app.Task): The task manager
          implementation specific task stub that exists server side to keep a
          reference to the remote task objects.  For PSQ this is a task result
          object, but other implementations have their own stub objects.
      tmp_dir (str): Temporary directory for Task to write to.
      requester (str): The user who requested the task.
      _evidence_config (dict): The config that we want to pass to all new
            evidence created from this task.
  """

  # The list of attributes that we will persist into storage
  STORED_ATTRIBUTES = [
      'id', 'job_id', 'last_update', 'name', 'request_id', 'requester'
  ]

  def __init__(
      self, name=None, base_output_dir=None, request_id=None, requester=None):
    """Initialization for TurbiniaTask."""
    if base_output_dir:
      self.base_output_dir = base_output_dir
    else:
      self.base_output_dir = config.OUTPUT_DIR

    self.id = uuid.uuid4().hex
    self.is_finalize_task = False
    self.job_id = None
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
    self.turbinia_version = turbinia.__version__
    self.requester = requester if requester else 'user_unspecified'
    self._evidence_config = {}

  def serialize(self):
    """Converts the TurbiniaTask object into a serializable dict.

    Returns:
      Dict: Dictionary representing this object, ready to be serialized.
    """
    task_copy = deepcopy(self.__dict__)
    task_copy['output_manager'] = self.output_manager.__dict__
    task_copy['last_update'] = self.last_update.strftime(DATETIME_FORMAT)
    return task_copy

  @classmethod
  def deserialize(cls, input_dict):
    """Converts an input dictionary back into a TurbiniaTask object.

    Args:
      input_dict (dict): TurbiniaTask object dictionary.

    Returns:
      TurbiniaTask: Deserialized object.
    """
    from turbinia import client  # Avoid circular imports

    type_ = input_dict['name']
    try:
      task = getattr(sys.modules['turbinia.client'], type_)()
    except AttributeError:
      message = (
          "Could not import {0:s} object! Make sure it is imported where "
          "this method is defined.".format(type_))
      log.error(message)
      raise TurbiniaException(message)
    task.__dict__.update(input_dict)
    task.output_manager = output_manager.OutputManager()
    task.output_manager.__dict__.update(input_dict['output_manager'])
    task.last_update = datetime.strptime(
        input_dict['last_update'], DATETIME_FORMAT)
    return task

  def execute(
      self, cmd, result, save_files=None, log_files=None, new_evidence=None,
      close=False, shell=False, success_codes=None):
    """Executes a given binary and saves output.

    Args:
      cmd (list|string): Command arguments to run
      result (TurbiniaTaskResult): The result object to put data into.
      save_files (list): A list of files to save (files referenced by Evidence
          objects are automatically saved, so no need to include them).
      log_files (list): A list of files to save even if execution fails.
      new_evidence (list): These are new evidence objects created by the task.
          If the task is successful, they will be added to the result.
      close (bool): Whether to close out the result.
      shell (bool): Whether the cmd is in the form of a string or a list.
      success_codes (list(int)): Which return codes are considered successful.

    Returns:
      Tuple of the return code, and the TurbiniaTaskResult object
    """
    save_files = save_files if save_files else []
    log_files = log_files if log_files else []
    new_evidence = new_evidence if new_evidence else []
    success_codes = success_codes if success_codes else [0]

    if shell:
      proc = subprocess.Popen(cmd, shell=True)
    else:
      proc = subprocess.Popen(cmd)
    stdout, stderr = proc.communicate()
    result.error['stdout'] = stdout
    result.error['stderr'] = stderr
    ret = proc.returncode

    for file_ in log_files:
      if not os.path.exists(file_):
        result.log(
            'Log file {0:s} does not exist to save'.format(file_),
            level=logging.DEBUG)
        continue
      if os.path.getsize(file_) == 0:
        result.log(
            'Log file {0:s} is empty. Not saving'.format(file_),
            level=logging.DEBUG)
        continue
      result.log('Output file at {0:s}'.format(file_))
      if not self.run_local:
        self.output_manager.save_local_file(file_, result)

    if ret not in success_codes:
      message = 'Execution of [{0!s}] failed with status {1:d}'.format(cmd, ret)
      result.log(message)
      if close:
        result.close(self, success=False, status=message)
    else:
      result.log('Execution of [{0!s}] succeeded'.format(cmd))
      for file_ in save_files:
        if os.path.getsize(file_) == 0:
          result.log(
              'Output file {0:s} is empty. Not saving'.format(file_),
              level=logging.DEBUG)
          continue
        result.log('Output file at {0:s}'.format(file_))
        if not self.run_local:
          self.output_manager.save_local_file(file_, result)

      for evidence in new_evidence:
        # If the local path is set in the Evidence, we check to make sure that
        # the path exists and is not empty before adding it.
        if evidence.local_path and not os.path.exists(evidence.local_path):
          message = (
              'Evidence {0:s} local_path {1:s} does not exist. Not returning '
              'empty Evidence.'.format(evidence.name, evidence.local_path))
          result.log(message, level=logging.WARN)
        elif (evidence.local_path and os.path.exists(evidence.local_path) and
              os.path.getsize(evidence.local_path) == 0):
          message = (
              'Evidence {0:s} local_path {1:s} is empty. Not returning '
              'empty new Evidence.'.format(evidence.name, evidence.local_path))
          result.log(message, level=logging.WARN)
        else:
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
          input_evidence=evidence, base_output_dir=self.base_output_dir,
          request_id=self.request_id, job_id=self.job_id)
      self.result.setup(self)

    if not self.run_local:
      if evidence.copyable and not config.SHARED_FILESYSTEM:
        self.output_manager.retrieve_evidence(evidence)

    if evidence.local_path and not os.path.exists(evidence.local_path):
      raise TurbiniaException(
          'Evidence local path {0:s} does not exist'.format(
              evidence.local_path))
    evidence.preprocess(self.tmp_dir)
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
      except (TypeError, pickle.PicklingError) as exception:
        bad_message = (
            'Error pickling TurbiniaTaskResult object. Returning a new result '
            'with the pickling error, and all previous result data will be '
            'lost. Pickle Error: {0!s}'.format(exception))

    if bad_message:
      log.error(bad_message)
      if result and hasattr(result, 'status') and result.status:
        old_status = result.status
      else:
        old_status = 'No previous status'

      result = TurbiniaTaskResult(
          base_output_dir=self.base_output_dir, request_id=self.request_id,
          job_id=self.job_id)
      result.setup(self)
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
      evidence (dict): To be decoded into Evidence object

    Returns:
      A TurbiniaTaskResult object
    """
    log.debug('Task {0:s} {1:s} awaiting execution'.format(self.name, self.id))
    evidence = evidence_decode(evidence)
    with filelock.FileLock(config.LOCK_FILE):
      log.info('Starting Task {0:s} {1:s}'.format(self.name, self.id))
      original_result_id = None
      try:
        self.result = self.setup(evidence)
        original_result_id = self.result.id
        evidence.validate()

        if self.turbinia_version != turbinia.__version__:
          message = (
              'Worker and Server versions do not match: {0:s} != {1:s}'.format(
                  self.turbinia_version, turbinia.__version__))
          self.result.log(message, level=logging.ERROR)
          self.result.status = message
          return self.result

        self._evidence_config = evidence.config
        self.result = self.run(evidence, self.result)
      # pylint: disable=broad-except
      except Exception as exception:
        message = (
            '{0:s} Task failed with exception: [{1!s}]'.format(
                self.name, exception))
        # Logging explicitly here because the result is in an unknown state
        trace = traceback.format_exc()
        log.error(message)
        log.error(trace)
        if self.result:
          self.result.log(message, level=logging.ERROR)
          self.result.log(trace)
          if hasattr(exception, 'message'):
            self.result.set_error(exception.message, traceback.format_exc())
          else:
            self.result.set_error(exception.__class__, traceback.format_exc())
          self.result.status = message
        else:
          log.error('No TurbiniaTaskResult object found after task execution.')

      self.result = self.validate_result(self.result)

      # Trying to close the result if possible so that we clean up what we can.
      # This has a higher likelihood of failing because something must have gone
      # wrong as the Task should have already closed this.
      if self.result and not self.result.closed:
        message = 'Trying last ditch attempt to close result'
        log.warning(message)
        self.result.log(message)

        if self.result.status:
          status = self.result.status
        else:
          status = 'No previous status'
        message = (
            'Task Result was auto-closed from task executor on {0:s} likely '
            'due to previous failures.  Previous status: [{1:s}]'.format(
                self.result.worker_name, status))
        self.result.log(message)
        try:
          self.result.close(self, False, message)
        # Using broad except here because lots can go wrong due to the reasons
        # listed above.
        # pylint: disable=broad-except
        except Exception as exception:
          log.error('TurbiniaTaskResult close failed: {0!s}'.format(exception))
          if not self.result.status:
            self.result.status = message
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
    return self.result.serialize()

  def run(self, evidence, result):
    """Entry point to execute the task.

    Args:
      evidence: Evidence object.
      result: A TurbiniaTaskResult object to place task results into.

    Returns:
        TurbiniaTaskResult object.
    """
    raise NotImplementedError
