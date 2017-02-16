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
  """Object to store task results to be returned by a TurbiniaTask."""

  def __init__(self, results=None, version=None, metadata=None):
    """Initialize the TurbiniaTaskResult object.

    Args:
        results: List of task execution results.
        version: Version of the program being executed.
        metadata: Dictionary of metadata from the task.
    """

    self.results = results
    self.version = version
    self.metadata = metadata

    if not self.results:
      self.results = list()
    if not self.metadata:
      self.metadata = dict()

  def add_result(self, result_type, result):
    """Populate the results list.

    Args:
        result_type: Type of result, e.g. URL or filesystem path.
        result: Result string from the task.
    """
    self.results.append(dict(type=result_type, result=result))

  def to_json(self):
    """Convert object to JSON."""
    return json.dumps(self.__dict__)


class TurbiniaTaskGroup(object):

  def __init__(self):
    self.current_task_id = None
    self.tasks = []

  @property
  def active_task(self):
    if self.current_task_id:
      return self.tasks[self.current_task_id]
    else:
      return None

  @active_task.setter
  def active_task(self, value):
    if value in self.tasks:
      self.current_task_id = self.tasks.index(value)
      return value
    else:
      return False

  def next_task(self):
    if len(self.tasks) - 1 > self.current_task_id:
      self.current_task_id += 1
      return self.tasks[self.current_task_id]
    else:
      self.current_task_id = None
      return False

  def add_task(self, task):
    self.tasks.append(task)


class TurbiniaTask(object):
  """Base class for Turbinia tasks."""

  def __init__(self, name=None):
    self.id = uuid.uuid4().hex
    self.name = name
    # Task is considered completed (or failed) if it has a result.
    self.result = None

  def run(self, *args, **kwargs):
    """Entry point to execute the task."""
    raise NotImplementedError


class TurbiniaWorkerStub(object):
  """Server side stub to hold remote worker data."""

  def __init__(self, id_=None, hostname=None):
    self.id = id_
    self.hostname = hostname
    self.creation_time = datetime.now()
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
    self.last_checkin_time = datetime.now()
    self.in_use = in_use
    self.active_job = active_job

