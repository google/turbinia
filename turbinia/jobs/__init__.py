#!/usr/bin/python
#
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
"""Turbinia jobs."""

from datetime import datetime
import json
import sys
import time
import traceback as tb
import uuid

from turbinia.workers import TurbiniaTaskGroup


class TurbiniaJobResult(object):
  """Class to hold a Turbinia job result."""
  def __init__(
      self, results=None, error=None, runtime=0, successful=False,
      job_type=None, job_id=None, version=None, metadata=None):
    """Initialize the TurbiniaJobResult class.

    Args:
        results: List of task execution results.
        error: Dictionary of error and traceback.
        runtime: Runtime in seconds the task executes.
        successful: True if success and False if error.
        job_type: Name of the TurbiniaJob class used.
        job_id: The unique id of the job.
        version: Version of the program executed.
        metadata: Dictionary of metadata from the task.
    """

    self.results = results
    self.error = error
    self.runtime = runtime
    self.successful = successful
    self.job_type = job_type
    self.job_id = job_id
    self.version = version
    self.metadata = metadata

    if not self.results:
      self.results = list()
    if not self.error:
      self.error = dict()
    if not self.metadata:
      self.metadata = dict()

  def set_error(self, error, traceback):
    """Add error and traceback.

    Args:
        error: Short string describing the error.
        traceback: Traceback of the error.
    """
    self.error['error'] = error
    self.error['traceback'] = traceback

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


class TurbiniaJob(object):
  """Base class for Turbinia CLI commands."""

  def __init__(self, name=None, output_path=None):
    self.name = name
    self.output_path = output_path
    self.id = uuid.uuid4().hex

    self.result = None
    self.current_task_id = None
    self.task = None
    # Job priority from 0-100, lowest == highest priority
    self.priority = 100

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

  def _calc_runtime(self, start_time):
    """Calculate the time delta between two datetimes.

    Args:
        start_time: Datetime object.

    Returns:
        Time delta in seconds from start_time to now.
    """
    return (datetime.now() - start_time).seconds

  def get_next_task(self):
    if len(self.tasks) - 1 > self.current_task_id:
      return self.tasks[self.current_task_id + 1]
    else:
      return False

  def set_next_task(self):
    next_task = self.get_next_task()
    if next_task:
      self.current_task_id += 1
      return self.tasks[self.current_task_id]
    else:
      self.current_task_id = None
      return False

  def add_task(self, task):
    self.tasks.append(task)

  def run(self, task, job_id):
    """Start a task execution.

    Args:
        task: A turbinia task (instance of turbinia.workers.TurbiniaTask)
        job_id: Unique id for the job.
    Returns:
        Job result object (instance of turbinia.jobs.TurbiniaJobResult)
    """
    start_time = datetime.now()
    result = TurbiniaJobResult(job_id=job_id)

    while not task.successful():
      if task.failed():
        task.revoke()
        result.successful = False
        result.runtime = self._calc_runtime(start_time)
        try:
          task.get()
        # TODO(aarontp): Scope this more narrowly
        except Exception as e:
          result.set_error(error=repr(e), traceback=tb.format_exc())
        return result
      time.sleep(1)

    job_result = json.loads(task.get())
    result.runtime = self._calc_runtime(start_time)
    result.successful = True
    result.metadata = job_result.get('metadata', dict())
    result.job_type = self.__class__.__name__
    result.version = job_result.get('version', 'Unknown')
    for r in job_result.get('results', list()):
      result.add_result(result_type=r['type'], result=r['result'])
    return result

  def run_cli(self, task, job_id):
    """Start a task execution from the CLI.

    Args:
        task: A turbinia task (instance of turbinia.workers.TurbiniaTask)
        job_id: Unique id for the job.
    """
    try:
      job = self.run(task, job_id)
      if not job.successful:
        sys.stderr.write(job.error['error'] + '\n')
        sys.stderr.flush()
        sys.exit(1)
      sys.stdout.write(job.results[0]['result'] + '\n')
      sys.stdout.flush()
      sys.exit(0)
    except KeyboardInterrupt:
      task.revoke(terminate=True)
      sys.exit(130)

  def create_task(self, task):
    """Create Turbinia task to be run."""
    raise NotImplementedError

  def cli(self, cmd_args):
    """Entry point for the CLI tool to start a task."""
    raise NotImplementedError
