# -*- coding: utf-8 -*-
# Copyright 2023 Google Inc.
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
"""Turbinia API server Request models."""

import datetime
import logging

from datetime import datetime
from datetime import timedelta
from operator import itemgetter
from pydantic import BaseModel, Extra
from typing import ClassVar

from turbinia import state_manager
from turbinia import config as turbinia_config

log = logging.getLogger(__name__)


class WorkersInfo(BaseModel, extra=Extra.allow):
  """Information about Workers."""

  workers_dict: ClassVar[dict] = {}
  unassigned_dict: ClassVar[dict] = {}
  scheduled_counter: ClassVar[int] = 0

  def get_workers_information(self, days: int = 7) -> bool:
    """Retrieves the general workers dict.

    Args:
      days (int): The number of days we want status for.
    
    Returns:
        bool: True if report was successfully acquired.
    """
    task_results = state_manager.get_state_manager().get_task_data(
        turbinia_config.INSTANCE_ID, days)

    # Sort task_results by last updated timestamp.
    task_results = sorted(
        task_results, key=itemgetter('last_update'), reverse=True)

    for result in task_results:
      worker_node = result.get('worker_name')
      status = result.get('status')
      status = status if status else 'No task status'
      if worker_node and worker_node not in self.workers_dict:
        self.workers_dict[worker_node] = []
      elif not worker_node:
        # Track scheduled/unassigned Tasks for reporting.
        self.scheduled_counter += 1
        worker_node = 'Unassigned'
        if worker_node not in self.unassigned_dict:
          self.unassigned_dict[worker_node] = []
      if worker_node:
        task_dict = {}
        task_dict['task_id'] = result.get('id')
        task_dict['last_update'] = result.get('last_update')
        task_dict['task_name'] = result.get('name')
        task_dict['status'] = status
        # Check status for anything that is running.
        if 'running' in status:
          run_time = (datetime.utcnow() -
                      result.get('last_update')).total_seconds()
          run_time = timedelta(seconds=run_time)
          task_dict['run_time'] = run_time
        else:
          run_time = result.get('run_time')
          task_dict['run_time'] = run_time if run_time else 'No run time.'
        # Update to correct dictionary
        if worker_node == 'Unassigned':
          self.unassigned_dict[worker_node].append(task_dict)
        else:
          self.workers_dict[worker_node].append(task_dict)

    return self.workers_dict or self.unassigned_dict or self.scheduled_counter


class WorkersStatus(BaseModel):
  """A json-serializable report of workers status."""

  status: ClassVar[dict] = {}

  def simplify_task_dict(
      self,
      task: dict,
  ) -> dict:
    """Creates a json-serializable dict for one Task.

    Args:
      task (dict): Original Task dictionary
    
    Returns:
      task_dict (dict): Json-serializable Task dictionary.
    """

    task_dict = {
        'task_name':
            task['task_name'],
        'last_update':
            task['last_update'].strftime(turbinia_config.DATETIME_FORMAT),
        'status':
            task['status'],
        'run_time':
            str(task['run_time'])
    }
    return task_dict

  def get_workers_status(self, days: int = 7, all_fields: bool = False) -> bool:
    """Formats the workers_dict with relevant and serializable information.
    
    Args:
      days (int): The number of days we want status for.
      all_fields (bool): Returns all status fields if set to true.

    Returns:
        bool: True if report was successfully acquired.
    """

    workers_info = WorkersInfo()

    if not workers_info.get_workers_information(days):
      return {}

    self.status['scheduled_tasks'] = workers_info.scheduled_counter

    for worker_node, tasks in workers_info.workers_dict.items():
      self.status[worker_node] = {}

      # Adds the statuses chronologically
      run_status, queued_status, other_status = {}, {}, {}
      for task in tasks:
        if 'running' in task['status']:
          run_status[task['task_id']] = self.simplify_task_dict(task)
        elif 'queued' in task['status']:
          queued_status[task['task_id']] = self.simplify_task_dict(task)
        else:
          other_status[task['task_id']] = self.simplify_task_dict(task)
        # Add each of the status lists back to report list
        self.status[worker_node]['run_status'] = run_status
        self.status[worker_node]['queued_status'] = queued_status
        # Add Finished Tasks
        if all_fields:
          self.status[worker_node]['other_status'] = other_status

      # Add unassigned worker tasks
      unassigned_status = {}
      for tasks in workers_info.unassigned_dict.values():
        for task in tasks:
          unassigned_status[task['task_id']] = self.simplify_task_dict(task)

      # Now add to main report
      if all_fields:
        self.status[worker_node]['unassigned_status'] = unassigned_status

    return self.status
