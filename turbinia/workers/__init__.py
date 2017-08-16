# Copyright 2015 Google Inc.
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

from datetime import datetime
import errno
import json
import logging
import os
import platform
import time
import uuid

from turbinia import TurbiniaException


class TurbiniaTaskResult(object):
  """Object to store task results to be returned by a TurbiniaTask.

  Attributes:
        error: Dict of error data ('error' and 'traceback' are some valid keys)
        evidence: List of newly created Evidence objects.
        input_evidence: The evidence this task processed.
        run_time: Length of time the task ran for.
        start_time: Datetime object of when the task was started
        status: A one line descriptive task status.
        successful: Bool indicating success status.
        task_id: Task ID of the parent task.
        task_name: Name of parent task.
        worker_name: Name of worker task executed on.
        _log: A list of log messages
  """

  def __init__(
      self,
      evidence=None,
      input_evidence=None,
      task_id=None,
      task_name=None,
      output_dir=None):
    """Initialize the TurbiniaTaskResult object."""

    self.evidence = evidence if evidence else []
    self.input_evidence = input_evidence if input_evidence else []
    self.task_id = task_id
    self.task_name = task_name
    self.output_dir = output_dir

    self.start_time = datetime.now()
    self.run_time = None
    self.successful = None
    self.status = None
    self.error = {}
    self.worker_name = platform.node()
    # TODO(aarontp): Create mechanism to grab actual python logging data.
    self._log = []

  def close(self, success, status=None):
    """Handles closing of this result and writing logs.

    Args:
      success: Bool indicating task success
      status: One line descriptive task status.
    """
    self.successful = success
    self.run_time = datetime.now() - self.start_time
    if not status:
      status = u'Completed successfully in {0:s} on {1:s}'.format(
          str(self.run_time), self.worker_name)
    if self.output_dir and os.path.exists(self.output_dir):
      logfile = os.path.join(self.output_dir, u'log.txt')
      with open(logfile, 'w') as f:
        f.write('\n'.join(self._log))
        f.write('\n')
    self.input_evidence.postprocess()
    self.status = status

  def log(self, log_msg):
    """Add a log message to the result object.

    Args:
      log_msg: A log message string.
    """
    logging.info(log_msg)
    self._log.append(log_msg)

  def add_evidence(self, evidence):
    """Populate the results list.

    Args:
        evidence: Evidence object
    """
    self.evidence.append(evidence)

  def set_error(self, error, traceback):
    """Add error and traceback.

    Args:
        error: Short string describing the error.
        traceback: Traceback of the error.
    """
    self.error['error'] = error
    self.error['traceback'] = traceback


class TurbiniaTask(object):
  """Base class for Turbinia tasks.

  Attributes:
      id: Unique Id of task (string of hex)
      name: Name of task
      base_output_dir: The base directory that output will go into.  Per-task
                       directories will be created under this.
      output_dir: The directory output will go into (including per-task folder).
      result: A TurbiniaTaskResult object.
  """

  def __init__(self, name=None, base_output_dir=None):
    """Initialization for TurbiniaTask."""
    self.id = uuid.uuid4().hex
    self.name = name if name else self.__class__.__name__
    self.base_output_dir = base_output_dir
    self.output_dir = None
    self.result = None

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
    self.create_output_dir()
    self.result = TurbiniaTaskResult(
        task_id=self.id,
        task_name=self.name,
        input_evidence=evidence,
        output_dir=self.output_dir)
    if evidence.local_path and not os.path.exists(evidence.local_path):
      raise TurbiniaException(
          'Evidence local path {0:s} does not exist'.format(
              evidence.local_path))
    evidence.preprocess()
    return self.result

  def create_output_dir(self):
    """Generates a unique output path for this task and creates directories.

    Needs to be run at runtime so that the task creates the directory locally.

    Returns:
      A local output path string.

    Raises:
      TurbiniaException: If there are failures creating the directory.
    """
    epoch = str(int(time.time()))
    logging.info('%s %s %s' % (epoch, str(self.id), self.name))
    dir_name = u'{0:s}-{1:s}-{2:s}'.format(epoch, str(self.id), self.name)
    new_dir = os.path.join(self.base_output_dir, dir_name)
    self.output_dir = new_dir
    if not os.path.exists(new_dir):
      try:
        logging.info('Creating new directory {0:s}'.format(new_dir))
        os.makedirs(new_dir)
        if self.result:
          self.result.log('Created output directory {0:s}'.format(new_dir))
      except OSError as e:
        if e.errno == errno.EACCESS:
          msg = u'Permission error ({0:s})'.format(str(e))
        else:
          msg = str(e)
        raise TurbiniaException(msg)

    return new_dir

  def run(self, evidence):
    """Entry point to execute the task.

    Args:
      evidence: Evidence object.

    Returns:
        TurbiniaTaskResult object.
    """
    raise NotImplementedError
