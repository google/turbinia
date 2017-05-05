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

import datetime
import json
import uuid


class TurbiniaTaskResult(object):
  """Object to store task results to be returned by a TurbiniaTask.

  Attributes:
        evidence: List of newly created Evidence objects.
        input_evidence: The evidence this task processed.
        task_id: Task ID of the parent task.
        task_name: Name of parent task.
        start_time: Datetime object of when the task was started
        run_time: Length of time the task ran for.
        successful: Bool indicating success status.
        error: Dict of error data ('error' and 'traceback' are some valid keys)
        _log: A list of log messages
  """

  def __init__(self, evidence=None, input_evidence=None, task_id=None,
               task_name=None):
    """Initialize the TurbiniaTaskResult object."""

    self.evidence = evidence if evidence else []
    self.input_evidence = input_evidence if input_evidence else []
    self.task_id = task_id
    self.task_name = task_name

    self.start_time = datetime.datetime.now()
    self.run_time = None
    self.successful = None
    self.error = {}
    # TODO(aarontp): Create mechanism to grab actual python logging data.
    self._log = []

  def log(self, log_msg):
    """Add a log message to the result object.

    Args:
      log_msg: A log message string.
    """
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
  """Base class for Turbinia tasks."""

  def __init__(self, name=None):
    self.id = uuid.uuid4().hex
    self.name = name
    self.result = None

  def create_result(self, input_evidence):
    """Generate a TurbiniaTaskResult object.

    Args:
      input_evidence: Turbinia Evidence object

    Returns:
      A TurbiniaTaskResult object.
    """
    self.result = TurbiniaTaskResult(task_id=self.id, task_name=self.name,
                                     input_evidence=input_evidence)
    return self.result

  def run(self, *args, **kwargs):
    """Entry point to execute the task."""
    raise NotImplementedError


# TODO(aarontp): Remove this?  Is there any use when using PSQ?
class TurbiniaWorkerStub(object):
  """Server side stub to hold remote worker data."""

  def __init__(self, id_=None, hostname=None):
    self.id = id_
    self.hostname = hostname
    self.creation_time = datetime.datetime.now()
    self.last_checkin_time = None
    # Data known from last heartbeat (and possibly stale)
    self.in_use = False
    # Id of the active job (or None if no active job)
    self.active_job = None

  def update_worker(self, in_use, active_job):
    """Updates the worker data from heartbeat data.

    Args:
      in_use: Boolean indicating whether the worker is in use by a task
      active_job: The id of the active job running in the Worker
    """
    self.last_checkin_time = datetime.datetime.now()
    self.in_use = in_use
    self.active_job = active_job

