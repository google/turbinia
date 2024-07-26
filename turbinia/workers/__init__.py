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

from copy import deepcopy
from datetime import datetime
from datetime import timedelta
from enum import IntEnum

from itertools import chain
import json
import logging
import os
import pickle
import platform
import pprint
import signal
import subprocess
import sys
import tempfile
import traceback
import uuid
import filelock

from prometheus_client import Counter, Histogram
from turbinia import __version__, config
from turbinia.config import DATETIME_FORMAT
from turbinia.evidence import evidence_decode
from turbinia.evidence import Evidence
from turbinia.processors import resource_manager
from turbinia import output_manager
from turbinia import state_manager
from turbinia import task_utils
from turbinia import TurbiniaException
from turbinia import log_and_report

from celery.exceptions import SoftTimeLimitExceeded
from prometheus_client import REGISTRY

METRICS = {}
# Set the maximum size that the report can be before truncating it.  This is a
# best effort estimate and not a guarantee and comes from the limit for
# datastore entities[1] less some overhead for the rest of the attributes that
# will be saved in the response.
# [1]https://cloud.google.com/datastore/docs/concepts/limits
REPORT_MAXSIZE = int(1048572 * 0.75)

log = logging.getLogger(__name__)

# Prevent re-registering metrics if module is loaded multiple times.
metric_names = list(chain.from_iterable(REGISTRY._collector_to_names.values()))
if 'turbinia_worker_exception_failure' not in metric_names:
  turbinia_worker_exception_failure = Counter(
      'turbinia_worker_exception_failure',
      'Total number Tasks failed due to uncaught exception')
  turbinia_worker_tasks_started_total = Counter(
      'turbinia_worker_tasks_started_total',
      'Total number of started worker tasks')
  turbinia_worker_tasks_completed_total = Counter(
      'turbinia_worker_tasks_completed_total',
      'Total number of completed worker tasks')
  turbinia_worker_tasks_queued_total = Counter(
      'turbinia_worker_tasks_queued_total',
      'Total number of queued worker tasks')
  turbinia_worker_tasks_failed_total = Counter(
      'turbinia_worker_tasks_failed_total',
      'Total number of failed worker tasks')
  turbinia_worker_tasks_timeout_total = Counter(
      'turbinia_worker_tasks_timeout_total',
      'Total number of worker tasks timed out during dependency execution.')
  turbinia_worker_tasks_timeout_celery_soft = Counter(
      'turbinia_worker_tasks_timeout_celery_soft',
      'Total number of Tasks timed out due to Celery soft timeout')


class Priority(IntEnum):
  """Reporting priority enum to store common values.

  Priorities can be anything in the range of 0-100, where 0 is the highest
  priority.
  """
  LOW = 80
  MEDIUM = 50
  HIGH = 20
  CRITICAL = 10


class TurbiniaTaskResult:
  """Object to store task results to be returned by a TurbiniaTask.

  Attributes:
      base_output_dir (str): Base path for local output
      closed (bool): Indicates whether this result is closed
      output_dir (str): Full path for local output
      error (dict): Error data ('error' and 'traceback' are some valid keys)
      evidence (list[Evidence]): Newly created Evidence objects.
      evidence_size (int): Size of evidence in bytes.
      id (str): Unique Id of result (string of hex)
      input_evidence (Evidence): The evidence this task processed.
      job_id (str): The ID of the Job that generated this Task/TaskResult
      report_data (string): Markdown data that can be used in a Turbinia report.
      report_priority (int): Value between 0-100 (0 is the highest priority) to
          be used to order report sections.
      request_id (str): The id of the initial request to process this evidence.
      run_time (datetime): Length of time the task ran for.
      saved_paths (list(str)): Paths where output has been saved.
      status (str): A one line descriptive task status.
      successful (bool): Indicates success status.
      task_id (str): Task ID of the parent task.
      task_name (str): Name of parent task.
      requester (str): The user who requested the task.
      state_manager (DatastoreStateManager|RedisStateManager): State manager
          object to handle syncing with storage.
      worker_name (str): Name of worker task executed on.
      _log (list[str]): A list of log messages
  """

  # The list of attributes that we will persist into storage
  STORED_ATTRIBUTES = [
      'worker_name', 'report_data', 'report_priority', 'run_time', 'status',
      'saved_paths', 'successful', 'evidence_size'
  ]

  def __init__(
      self, evidence=None, input_evidence=None, base_output_dir=None,
      request_id=None, job_id=None, no_output_manager=False,
      no_state_manager=False):
    """Initialize the TurbiniaTaskResult object."""

    self.closed = False
    self.evidence = evidence if evidence else []
    self.evidence_size = None
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
    self.run_time = None
    self.saved_paths = []
    self.successful = None
    self.status = None
    self.error = {}
    self.worker_name = platform.node()
    self.state_manager = None
    # TODO(aarontp): Create mechanism to grab actual python logging data.
    self._log = []
    self.no_output_manager = no_output_manager
    self.no_state_manager = no_state_manager

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
    if not self.no_state_manager:
      self.state_manager = state_manager.get_state_manager()
    if not self.no_output_manager:
      if task.output_manager.is_setup:
        ldirs = task.output_manager.get_local_output_dirs()
        _, self.output_dir = ldirs
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
    if task.worker_start_time:
      self.run_time = datetime.now() - task.worker_start_time
    if success:
      turbinia_worker_tasks_completed_total.inc()
    else:
      turbinia_worker_tasks_failed_total.inc()
    if not status and self.successful:
      status = 'Completed successfully in {0:s} on {1:s}'.format(
          str(self.run_time), self.worker_name)
    elif not status and not self.successful:
      status = f'Run failed in {str(self.run_time):s} on {self.worker_name:s}'
    self.log(status)
    self.status = status

    for evidence in self.evidence:
      if evidence.source_path:
        if os.path.exists(evidence.source_path):
          self.saved_paths.append(evidence.source_path)
          if evidence.copyable:
            task.output_manager.save_evidence(evidence, self)
        else:
          self.log(
              'Evidence {0:s} has missing file at source_path {1!s} so '
              'not saving.'.format(evidence.name, evidence.source_path))
      else:
        self.log(
            f'Evidence {evidence.name:s} has empty source_path so not saving.')

      # Truncate report text data if it is approaching the size of the max
      # datastore entity size (See REPORT_MAXSIZE definition for details).
      if (hasattr(evidence, 'text_data') and evidence.text_data and
          len(evidence.text_data) > REPORT_MAXSIZE):
        message = (
            'The text_data attribute has a size {0:d} larger than the max '
            'size {1:d} so truncating the response.'.format(
                len(evidence.text_data), REPORT_MAXSIZE))
        self.log(message, logging.WARNING)
        evidence.text_data = evidence.text_data[:REPORT_MAXSIZE] + '\n'
        evidence.text_data += message

      if not evidence.request_id:
        evidence.request_id = self.request_id

    if self.input_evidence:
      try:
        self.input_evidence.postprocess(task_id=self.task_id)
      # Adding a broad exception here because we want to try post-processing
      # to clean things up even after other failures in the task, so this could
      # also fail.
      # pylint: disable=broad-except
      except Exception as exception:
        message = 'Evidence post-processing for {0!s} failed: {1!s}'.format(
            self.input_evidence.name, exception)
        self.log(
            message, level=logging.ERROR, traceback_=traceback.format_exc())
        with filelock.FileLock(config.RESOURCE_FILE_LOCK):
          resource_manager.PostProcessResourceState(
              self.input_evidence.resource_id, self.task_id)
    else:
      self.log(
          'No input evidence attached to the result object so post-processing '
          'cannot be run. This usually means there were previous failures '
          'during Task execution and this may result in resources (e.g. '
          'mounted disks) accumulating on the Worker.', level=logging.WARNING)

    # Updates evidence objects in Redis
    if self.state_manager:
      for evidence in self.evidence:
        if isinstance(evidence, Evidence):
          try:
            evidence.validate_attributes()
          except TurbiniaException as exception:
            log.error(f'Error updating evidence in redis: {exception}')
          else:
            self.state_manager.write_evidence(
                evidence.serialize(json_values=True))

    # Now that we've post-processed the input_evidence, we can unset it
    # because we don't need to return it.
    self.input_evidence = None

    if not self.no_output_manager:
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
        task.output_manager.save_local_file(logfile, self)

    self.closed = True
    log.debug(f'Result close successful. Status is [{self.status:s}]')

  def log(self, message, level=logging.INFO, traceback_=None):
    """Log Task messages.

    Logs to both the result and the normal logging mechanism.

    Args:
      message (string): Message to log.
      level (int): Log level as defined by logging enums (e.g. logging.INFO)
      traceback_ (string): Trace message to log
    """
    self._log.append(message)
    if level == logging.DEBUG:
      log.debug(message)
    elif level == logging.INFO:
      log.info(message)
    elif level == logging.WARNING:
      log.warning(message)
    elif level == logging.ERROR:
      log.error(message)
    elif level == logging.CRITICAL:
      log.critical(message)

    if traceback_:
      self.set_error(message, traceback_)

  def add_evidence(self, evidence, evidence_config):
    """Populate the results list.

    Args:
        evidence: Evidence object
        evidence_config (dict): The evidence config we want to associate with
            this object.  This will be passed in with the original evidence that
            was supplied to the task, so likely the caller will always want to
            use evidence_.config for this parameter.
    """
    if (evidence.source_path and os.path.exists(evidence.source_path) and
        os.path.getsize(evidence.source_path) == 0):
      self.log(
          'Evidence source path [{0:s}] for [{1:s}] exists but is empty. Not '
          'adding empty Evidence.'.format(evidence.source_path, evidence.name),
          logging.WARNING)
      return

    # We want to enforce this here to make sure that any new Evidence objects
    # created also contain the config.  We could create a closure to do this
    # automatically, but the real fix is to attach this to a separate object.
    # See https://github.com/google/turbinia/issues/211 for more details.
    evidence.config = evidence_config
    if evidence.context_dependent:
      evidence.set_parent(self.input_evidence)

    self.evidence.append(evidence)

  def set_error(self, error, traceback_):
    """Add error and traceback.

    Args:
        error: Short string describing the error.
        traceback_: Traceback of the error.
    """
    self.error['error'] = str(error)
    self.error['traceback'] = str(traceback_)

  def serialize(self):
    """Creates serialized result object.

    Returns:
      dict: Object dictionary that is JSON serializable.
    """
    self.state_manager = None
    result_copy = deepcopy(self.__dict__)
    if self.run_time:
      result_copy['run_time'] = self.run_time.total_seconds()
    else:
      result_copy['run_time'] = None
    if self.input_evidence:
      result_copy['input_evidence'] = None
    result_copy['evidence'] = [x.serialize() for x in self.evidence]

    return result_copy

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
    if result.state_manager:
      result.state_manager = state_manager.get_state_manager()
    if result.run_time:
      result.run_time = timedelta(seconds=result.run_time)
    if result.input_evidence:
      result.input_evidence = evidence_decode(result.input_evidence)
    result.evidence = [evidence_decode(x) for x in result.evidence]

    return result


class TurbiniaTask:
  """Base class for Turbinia tasks.

  Attributes:
      _evidence_config (dict): The config that we want to pass to all new
          evidence created from this task.
      base_output_dir (str): The base directory that output will go into.
          Per-task directories will be created under this.
      evidence (list): List of Evidence objects.
      evidence_size (int): The size of the evidence.
      group_id (str): group id for the evidence
      group_name (str): group name for the evidence
      id (str): Unique Id of task (string of hex)
      is_finalize_task (bool): Whether this is a finalize Task or not.
      job_id (str): Job ID the Task was created by.
      job_name (str): The name of the Job.
      last_update (datetime): A datetime object with the last time the task was
          updated.
      name (str): Name of task
      output_dir (str): The directory output will go into (including per-task
          folder).
      output_manager (OutputManager): The object that manages saving output.
      reason (str): reason of the evidence
      recipe (dict): Validated recipe to be used as the task configuration.
      request_id (str): The id of the initial request to process this evidence.
      requester (str): The user who requested the task.
      result (TurbiniaTaskResult): A TurbiniaTaskResult object.
      start_time (datetime): When the task was started
      state_key (str): A key used to manage task state
      state_manager (state_manager): Turbinia state manager object.
      stub (celery.result.AsyncResult): The task manager implementation
          specific task stub that exists server side to keep a reference to the
          remote task objects.
      task_config (dict): Default task configuration, in effect if no recipe is
          explicitly provided for the task.
      tmp_dir (str): Temporary directory for Task to write to.
      turbinia_version (str): The version of Turbinia that was used to run the
          task.
      worker_start_time (datetime): The time the worker started the task.
      """

  # The list of attributes that we will persist into storage
  STORED_ATTRIBUTES = [
      'id', 'job_id', 'job_name', 'start_time', 'last_update', 'name',
      'evidence_name', 'evidence_id', 'request_id', 'requester', 'group_name',
      'reason', 'group_id'
  ]

  # The list of evidence states that are required by a Task in order to run.
  # See `evidence.Evidence.preprocess()` docstrings for more details.
  REQUIRED_STATES = []

  # The default configuration variables used by Tasks.  Recipe data will
  # override these parameters at run time.
  TASK_CONFIG = {}

  def __init__(
      self, name=None, base_output_dir=None, request_id=None, requester=None,
      group_name=None, reason=None, group_id=None):
    """Initialization for TurbiniaTask.

    Args:
      base_output_dir(str): Output dir to store Turbinia results.
      request_id(str): The request id
      requester(str): Name of the requester
      group_id(str): The group id
    """
    if base_output_dir:
      self.base_output_dir = base_output_dir
    else:
      self.base_output_dir = config.OUTPUT_DIR

    self.id = uuid.uuid4().hex
    self.is_finalize_task = False
    self.job_id = None
    self.job_name = None
    self.last_update = datetime.now()
    self.name = name if name else self.__class__.__name__
    self.evidence_name = None
    self.evidence_id = None
    self.output_dir = None
    self.output_manager = output_manager.OutputManager()
    self.state_manager = state_manager.get_state_manager()
    self.result = None
    self.request_id = request_id
    self.state_key = None
    self.start_time = datetime.now()
    self.worker_start_time = None
    self.stub = None
    self.tmp_dir = None
    self.turbinia_version = __version__
    self.requester = requester if requester else 'user_unspecified'
    self._evidence_config = {}
    self.recipe = {}
    self.task_config = {}
    self.group_name = group_name
    self.reason = reason
    self.group_id = group_id
    self.worker_name = platform.node()

  def serialize(self):
    """Converts the TurbiniaTask object into a serializable dict.

    Returns:
      Dict: Dictionary representing this object, ready to be serialized.
    """
    self.state_manager = None
    task_copy = deepcopy(self.__dict__)
    task_copy['output_manager'] = self.output_manager.__dict__
    task_copy['last_update'] = self.last_update.strftime(DATETIME_FORMAT)
    task_copy['start_time'] = self.start_time.strftime(DATETIME_FORMAT)
    return task_copy

  @classmethod
  def deserialize(cls, input_dict):
    """Converts an input dictionary back into a TurbiniaTask object.

    Args:
      input_dict (dict): TurbiniaTask object dictionary.

    Returns:
      TurbiniaTask: Deserialized object.
    """
    return task_utils.task_deserialize(input_dict)

  @classmethod
  def check_worker_role(cls):
    """Checks whether the execution context is within a worker or nosetests.

    Returns:
      bool: If the current execution is in a worker or nosetests.
    """
    config.LoadConfig()
    if config.TURBINIA_COMMAND in ('celeryworker', 'psqworker'):
      return True

    if 'unittest' in sys.modules.keys():
      return True

    return False

  def evidence_setup(self, evidence):
    """Validates and processes the evidence.

    Args:
      evidence(Evidence): The Evidence to setup.

    Raises:
      TurbiniaException: If the Evidence can't be validated or the current
          state does not meet the required state.
    """
    evidence.validate()
    evidence.preprocess(
        self.id, tmp_dir=self.tmp_dir, required_states=self.REQUIRED_STATES)
    self.evidence_name = evidence.name
    self.evidence_id = evidence.id

    # Final check to make sure that the required evidence state has been met
    # for Evidence types that have those capabilities.
    for state in self.REQUIRED_STATES:
      if state in evidence.POSSIBLE_STATES and not evidence.state.get(state):
        raise TurbiniaException(
            'Evidence {0!s} being processed by Task {1:s} requires Evidence '
            'to be in state {2:s}, but earlier pre-processors may have '
            'failed.  Current state is {3:s}. See previous logs for more '
            'information.'.format(
                evidence, self.name, state.name, evidence.format_state()))

  def validate_task_conf(self, proposed_conf):
    """Checks if the provided recipe contains exclusively allowed fields.
    Args:
      proposed_conf (dict): Dict to override the default dynamic task conf.

    Returns:
      bool: False if a field not present in the default dynamic task config
          is found.
    """
    if not proposed_conf:
      return False
    for k in proposed_conf.keys():
      if k == 'task':
        continue
      if k not in self.TASK_CONFIG:
        self.result.log(
            'Recipe key "{0:s}" is not found in task {1:s} default config: {2!s}'
            .format(k, self.name, self.TASK_CONFIG))
        return False
    return True

  def get_metrics(self):
    """Gets histogram metric for current Task.

    Returns:
      prometheus_client.Histogram: For the current task,
          or None if they are not initialized.

    Raises:
      TurbiniaException: If no metric is found for the given Task.
    """
    global METRICS
    metric = METRICS.get(self.name.lower())
    if not metric:
      message = (
          'No metric found for Task {0:s}. client.TASK_MAP may be out of '
          'date.'.format(self.name.lower))
      raise TurbiniaException(message)
    return metric

  def execute(
      self, cmd, result, save_files=None, log_files=None, new_evidence=None,
      close=False, shell=False, stderr_file=None, stdout_file=None,
      success_codes=None, cwd=None, env=None, timeout=0):
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
      stderr_file (str): Path to location to save stderr.
      stdout_file (str): Path to location to save stdout.
      cwd (str): Sets the current directory before the process is executed.
      env (list(str)): Process environment.
      timeout (int): Override job timeout value.

    Returns:
      Tuple of the return code, and the TurbiniaTaskResult object
    """
    # Avoid circular dependency.
    import psutil
    from turbinia.jobs import manager as job_manager

    save_files = save_files if save_files else []
    log_files = log_files if log_files else []
    new_evidence = new_evidence if new_evidence else []
    success_codes = success_codes if success_codes else [0]
    stdout = None
    stderr = None
    fail_message = None

    # Get timeout value.
    if timeout:
      timeout_limit = timeout
    else:
      timeout_limit = job_manager.JobsManager.GetTimeoutValue(self.job_name)

    # Execute the job via docker.
    docker_image = job_manager.JobsManager.GetDockerImage(self.job_name)
    if docker_image:
      from turbinia.lib import docker_manager
      ro_paths = []
      for path in ['local_path', 'source_path', 'device_path', 'mount_path']:
        if hasattr(result.input_evidence, path):
          path_string = getattr(result.input_evidence, path)
          if path_string:
            ro_paths.append(path_string)
      rw_paths = [self.output_dir, self.tmp_dir]
      container_manager = docker_manager.ContainerManager(docker_image)
      result.log(
          'Executing job {0:s} ({1:s}) in container: {2:s}'.format(
              self.job_name, self.job_id, docker_image))
      stdout, stderr, ret = container_manager.execute_container(
          cmd, shell, ro_paths=ro_paths, rw_paths=rw_paths,
          timeout_limit=timeout_limit)
    # Execute the job on the host system.
    else:
      try:
        if shell:
          proc = subprocess.Popen(
              cmd, shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE,
              cwd=cwd, env=env, text=True, encoding="utf-8")
          stdout, stderr = proc.communicate(timeout=timeout_limit)
        else:
          proc = subprocess.Popen(
              cmd, stderr=subprocess.PIPE, stdout=subprocess.PIPE, cwd=cwd,
              env=env, text=True, encoding="utf-8")
          stdout, stderr = proc.communicate(timeout=timeout_limit)
      except (subprocess.TimeoutExpired, SoftTimeLimitExceeded) as exception:
        # Catching the celery soft time limit here in addition to in the
        # `run_wrapper()` so we can allow this except block to clean up the
        # child processes appropriately when we are in this method.
        if isinstance(exception, SoftTimeLimitExceeded):
          timeout_type = 'celery soft'
          turbinia_worker_tasks_timeout_celery_soft.inc()
        else:
          timeout_type = 'subprocess'
        result.log(
            'Job {0:s} with Task {1:s} has reached {2:s} timeout limit of '
            '{3:d} so killing child processes.'.format(
                self.job_id, self.id, timeout_type, timeout_limit))
        # Kill child processes and parent process so we can return, otherwise
        # communicate() will hang waiting for the grand-children to be reaped.
        psutil_proc = psutil.Process(proc.pid)
        for child in psutil_proc.children(recursive=True):
          child.send_signal(signal.SIGKILL)
        proc.kill()
        # Get any potential partial output so we can save it later.
        stdout, stderr = proc.communicate()
        fail_message = (
            'Execution of [{0!s}] failed due to {1:s} timeout of '
            '{2:d} seconds has been reached.'.format(
                cmd, timeout_type, timeout_limit))
        result.log(fail_message)
        # Increase timeout metric. Not re-raising an exception so we can save
        # any potential output.
        turbinia_worker_tasks_timeout_total.inc()

      ret = proc.returncode

    result.error['stderr'] = str(stderr)

    if stderr_file and not stderr:
      result.log(
          'Attempting to save stderr to {0:s}, but no stderr found during '
          'execution'.format(stderr_file))
    elif stderr:
      if not stderr_file:
        _, stderr_file = tempfile.mkstemp(
            suffix='.txt', prefix='stderr-', dir=self.output_dir)
      result.log(f'Writing stderr to {stderr_file:s}', level=logging.DEBUG)
      with open(stderr_file, 'w+') as fh:
        fh.write(stderr)
      log_files.append(stderr_file)

    if stdout_file and not stdout:
      result.log(
          'Attempting to save stdout to {0:s}, but no stdout found during '
          'execution'.format(stdout_file))
    elif stdout:
      if not stdout_file:
        _, stdout_file = tempfile.mkstemp(
            suffix='.txt', prefix='stdout-', dir=self.output_dir)
      result.log(f'Writing stdout to {stdout_file:s}', level=logging.DEBUG)
      with open(stdout_file, 'w+') as fh:
        fh.write(stdout)
      log_files.append(stdout_file)

    log_files = list(set(log_files))
    for file_ in log_files:
      if not os.path.exists(file_):
        result.log(
            f'Log file {file_:s} does not exist to save', level=logging.DEBUG)
        continue
      if os.path.getsize(file_) == 0:
        result.log(
            f'Log file {file_:s} is empty. Not saving', level=logging.DEBUG)
        continue
      result.log(f'Output log file found at {file_:s}')
      self.output_manager.save_local_file(file_, result)

    if fail_message:
      result.close(self, success=False, status=fail_message)
    elif ret not in success_codes:
      message = f'Execution of [{cmd!s}] failed with status {ret:d}'
      result.log(message)
      if close:
        result.close(self, success=False, status=message)
    else:
      result.log(f'Execution of [{cmd!s}] succeeded')
      for file_ in save_files:
        if os.path.getsize(file_) == 0:
          result.log(
              f'Output file {file_:s} is empty. Not saving',
              level=logging.DEBUG)
          continue
        result.log(f'Output save file at {file_:s}')
        self.output_manager.save_local_file(file_, result)

      for evidence in new_evidence:
        # If the local path is set in the Evidence, we check to make sure that
        # the path exists and is not empty before adding it.
        if evidence.source_path and not os.path.exists(evidence.source_path):
          message = (
              'Evidence {0:s} source_path {1:s} does not exist. Not returning '
              'empty Evidence.'.format(evidence.name, evidence.source_path))
          result.log(message, level=logging.WARN)
        elif (evidence.source_path and os.path.exists(evidence.source_path) and
              os.path.getsize(evidence.source_path) == 0):
          message = (
              'Evidence {0:s} source_path {1:s} is empty. Not returning '
              'empty new Evidence.'.format(evidence.name, evidence.source_path))
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
    self.setup_metrics()
    self.output_manager.setup(self.name, self.id, self.request_id)
    self.tmp_dir, self.output_dir = self.output_manager.get_local_output_dirs()
    if not self.result:
      self.result = self.create_result(input_evidence=evidence)
    if evidence.copyable and not config.SHARED_FILESYSTEM:
      self.output_manager.retrieve_evidence(evidence)

    if evidence.source_path and not os.path.exists(evidence.source_path):
      raise TurbiniaException(
          f'Evidence source path {evidence.source_path:s} does not exist')
    return self.result

  def setup_metrics(self, task_list=None):
    """Sets up the application metrics.

    Returns early with metrics if they are already setup.

    Arguments:
      task_list(list): List of Task names

    Returns:
      Dict: Mapping of task names to metrics objects.
    """
    global METRICS

    if METRICS:
      return METRICS

    if not task_list:
      task_loader = task_utils.TaskLoader()
      task_list = task_loader.get_task_names()

    for task_name in task_list:
      task_name = task_name.lower()
      if task_name in METRICS:
        continue
      metric = Histogram(
          f'{task_name:s}_duration_seconds', f'Seconds to run {task_name:s}')
      METRICS[task_name] = metric

    log.debug(f'Registered {len(METRICS):d} task metrics')

    return METRICS

  def touch(self):
    """Updates the last_update time of the task."""
    self.last_update = datetime.now()

  def create_result(
      self, input_evidence=None, status=None, message=None, trace=None,
      no_output_manager=False):
    """Creates a new TurbiniaTaskResults and instantiates the result.

    Args:
      input_evidence(Evidence): The evidence being processed by this Task.
      status(str): A one line descriptive task status.
      message(str): An error message to show when returning the result.
      trace: Stack traceback for errors.
      no_output_manager(bool): Whether to create an output manager for the task.
    """
    result = TurbiniaTaskResult(
        base_output_dir=self.base_output_dir, request_id=self.request_id,
        job_id=self.job_id, input_evidence=input_evidence,
        no_output_manager=no_output_manager)
    result.setup(self)
    if message:
      if status:
        result.status = f'{message:s}. Previous status: [{status:s}]'
      else:
        result.status = message
      result.set_error(message, trace)
    return result

  def check_serialization_errors(self, result):
    """Checks the TurbiniaTaskResult is valid for serialization.

    This method checks the 'result'' object is the correct type and whether
    it is pickle/JSON serializable or not.

    Args:
      result(TurbiniaTaskResult): A TurbiniaTaskResult object.

    Returns:
      str | None: An error message, or None.
    """
    error_message = None

    # Check for serialization errors
    if isinstance(result, TurbiniaTaskResult):
      try:
        log.debug('Checking TurbiniaTaskResult for pickle serializability')
        pickle.dumps(result.serialize())
      except (TypeError, pickle.PicklingError) as exception:
        error_message = (
            f'Error pickling TurbiniaTaskResult object. Returning a new result '
            f'with the pickling error, and all previous result data will be '
            f'lost. Pickle Error: {exception!s}')
      try:
        log.debug('Checking TurbiniaTaskResult for JSON serializability')
        json.dumps(result.serialize())
      except (TypeError) as exception:
        error_message = (
            f'Error JSON serializing TurbiniaTaskResult object. Returning a new'
            f' result with the JSON error, and all previous result data will '
            f'be lost. JSON Error: {exception!s}')
    else:
      error_message = (
          f'Task returned type [{type(result)!s}] instead of '
          f'TurbiniaTaskResult.')

    return error_message

  def validate_result(self, result):
    """Checks to make sure that the result is valid.

    This method runs validation logic defined in Evidence.validate() to
    ensure that newly created evidence is usable as input for TurbiniaTask
    objects.

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
    serialization_error = self.check_serialization_errors(result)
    validation_error = None
    check_status = 'Successful'

    # Validate the new evidence objects
    if not serialization_error:
      for evidence in result.evidence[:]:
        try:
          evidence.validate()
        except TurbiniaException as exception:
          validation_error = (
              f'Not adding evidence {evidence.source_path}. Evidence '
              f'validation failed with error: {exception!s}')
          result.evidence.remove(evidence)
          result.saved_paths.remove(evidence.source_path)
      # Append evidence validation error messages to the result
      # so the client knows what happened
      if validation_error:
        result.log(validation_error)
        result.status = f'{result.status}. {validation_error}'
    else:
      # Handle any serialization type errors
      log.error(serialization_error)
      if result and hasattr(result, 'status') and result.status:
        status = result.status
      else:
        status = 'No previous status'

      result = self.create_result(
          status=status, message=serialization_error,
          trace=traceback.format_exc())
      result.close(self, success=False, status=serialization_error)
      check_status = 'Failed, but replaced with empty result'

    log.info(f'Result check: {check_status:s}')
    return result

  def get_task_recipe(self, recipe):
    """Creates and validates a recipe for the specified task.

    Args:
      recipe (dict): The full request recipe data.

    Returns:
      Dict: Recipe data specific to the current Task
    """
    recipe_data = deepcopy(self.TASK_CONFIG)
    for _, task_recipe in recipe.items():
      if isinstance(task_recipe, dict):
        task = task_recipe.get('task', None)
        if task and task == self.name and self.validate_task_conf(task_recipe):
          log.debug(f'Setting recipe data for task {task:s}: {task_recipe!s}')
          recipe_data.update(task_recipe)
          recipe_data.pop('task')
          break
    recipe_data.update(recipe['globals'])

    return recipe_data

  def run_wrapper(self, evidence):
    """Wrapper to manage TurbiniaTaskResults and exception handling.

    This wrapper should be called to invoke the run() methods so it can handle
    the management of TurbiniaTaskResults and the exception handling.  Otherwise
    details from exceptions in the worker cannot be propagated back to the
    Turbinia TaskManager.

    This method should handle (in no particular order):
      - Exceptions thrown from run()
      - Verifying valid TurbiniaTaskResult object is returned
          - Check for bad results (non TurbiniaTaskResults) returned from run()
          - Auto-close results that haven't been closed
          - Verifying that the results are serializeable
      - Locking to make sure only one task is active at a time

    Args:
      evidence (dict): To be decoded into Evidence object

    Returns:
      A TurbiniaTaskResult object
    """
    # Avoid circular dependency.
    from turbinia.jobs import manager as job_manager

    log.debug(f'Task {self.name:s} {self.id:s} awaiting execution')
    failure_message = None
    try:
      evidence = evidence_decode(evidence)
      self.result = self.setup(evidence)
      self.update_task_status(self, 'queued')
      turbinia_worker_tasks_queued_total.inc()
      task_runtime_metrics = self.get_metrics()
    except TurbiniaException as exception:
      message = (
          f'{self.name:s} Task setup failed with exception: [{exception!s}]')
      # Logging explicitly here because the result is in an unknown state
      trace = traceback.format_exc()
      log.error(message)
      log.error(trace)
      if self.result:
        if hasattr(exception, 'message'):
          self.result.set_error(exception.message, traceback.format_exc())
        else:
          self.result.set_error(exception.__class__, traceback.format_exc())
        self.result.status = message
      else:
        self.result = self.create_result(
            message=message, trace=traceback.format_exc())
      self.result.close(self, success=False)
      return self.result.serialize()

    log.info(f'Starting Task {self.name:s} {self.id:s}')
    original_result_id = None
    turbinia_worker_tasks_started_total.inc()
    with task_runtime_metrics.time():
      try:
        original_result_id = self.result.id

        # Check if Task's job is available for the worker.
        active_jobs = list(job_manager.JobsManager.GetJobNames())
        if self.job_name.lower() not in active_jobs:
          message = (
              'Task will not run due to the job: {0:s} being disabled '
              'on the worker.'.format(self.job_name))
          self.result.log(message, level=logging.ERROR)
          self.result.status = message
          return self.result.serialize()

        self.evidence_setup(evidence)
        self.result.evidence_size = evidence.size

        if config.VERSION_CHECK:
          if self.turbinia_version != __version__:
            message = (
                'Worker and Server versions do not match: {0:s} != {1:s}'
                .format(self.turbinia_version, __version__))
            self.result.log(message, level=logging.ERROR)
            self.result.status = message
            self.result.successful = False
            return self.result.serialize()

        self._evidence_config = evidence.config
        self.task_config = self.get_task_recipe(evidence.config)
        self.worker_start_time = datetime.now()
        self.update_task_status(self, 'running')
        self.result = self.run(evidence, self.result)

      # pylint: disable=broad-except
      except SoftTimeLimitExceeded as exception:
        failure_message = (
            f'{self.name:s} Task timed out via Celery soft limit: {exception}')
        if self.result:
          self.result.log(failure_message, level=logging.ERROR)
        else:
          log.error(failure_message)
        turbinia_worker_tasks_timeout_celery_soft.inc()

      except Exception as exception:
        failure_message = (
            f'{self.name:s} Task failed with exception: [{exception!s}]')
        # Logging explicitly here because the result is in an unknown state
        trace = traceback.format_exc()
        log_and_report(failure_message, trace)

        if self.result:
          self.result.log(failure_message, level=logging.ERROR)
          self.result.log(trace)
          if hasattr(exception, 'message'):
            self.result.set_error(exception.message, traceback.format_exc())
          else:
            self.result.set_error(exception.__class__, traceback.format_exc())
          self.result.status = failure_message
        else:
          log.error('No TurbiniaTaskResult object found after task execution.')
        turbinia_worker_exception_failure.inc()

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
      # Failure message can be set during previous exception handling.
      if not failure_message:
        failure_message = (
            'Task Result was auto-closed from task executor on {0:s} likely '
            'due to previous failures.  Previous status: [{1:s}]'.format(
                self.result.worker_name, status))
      self.result.log(failure_message)
      try:
        self.result.close(self, False, failure_message)
      # Using broad except here because lots can go wrong due to the reasons
      # listed above.
      # pylint: disable=broad-except
      except Exception as exception:
        log.error(f'TurbiniaTaskResult close failed: {exception!s}')
        if not self.result.status:
          self.result.status = failure_message
      # Check the result again after closing to make sure it's still good.
      self.result = self.validate_result(self.result)

    if original_result_id != self.result.id:
      log.debug(
          'Result object {0:s} is different from original {1!s} after task '
          'execution which indicates errors during execution'.format(
              self.result.id, original_result_id))
    else:
      log.debug(
          f'Returning original result object {self.result.id:s} after task execution'
      )
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

  def update_task_status(self, task, status=None):
    """Updates the task status and pushes it directly to datastore.

    Args:
      task (TurbiniaTask): The calling Task object
      status (str): Brief word or phrase for Task state. If not supplied, the
          existing Task status will be used.
    """
    if status:
      task.status = 'Task {0!s} is {1!s} on {2!s}'.format(
          self.name, status, self.worker_name)
    if not self.state_manager:
      self.state_manager = state_manager.get_state_manager()
    if self.state_manager:
      task_key = self.state_manager.redis_client.build_key_name('task', task.id)
      self.state_manager.redis_client.set_attribute(
          task_key, 'status', json.dumps(status))
      self.state_manager.update_request_task(task)
    else:
      log.info('No state_manager initialized, not updating Task info')
