# -*- coding: utf-8 -*-
# Copyright 2022 Google Inc.
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

from typing import Optional, List, Dict
from pydantic import BaseModel
from turbinia import state_manager
from turbinia import config as turbinia_config

log = logging.getLogger('turbinia:api_server:routes:request')


class RequestStatus(BaseModel):
  """Represents a Turbinia request status object."""
  request_id: str = None
  tasks: List[Dict] = []
  reason: str = None
  requester: str = None
  last_task_update_time: str = None
  status: str = None
  task_count: int = 0
  successful_tasks: int = 0
  running_tasks: int = 0
  failed_tasks: int = 0
  queued_tasks: int = 0

  def get_request_data(
      self, request_id: str, tasks: Optional[List[Dict]] = None,
      summary: bool = False) -> bool:
    """Gets task information for a specific Turbinia request.

    Args:
      request_id (str): A Turbinia request identifier.
      tasks (Optional[List[Dict]]): an optional list of task objects.
      summary (bool): If this flag is set, the 'tasks' list will be empty.

    Returns:
      bool: True if the request has at least one task associated with it.
    """
    if not tasks:
      _state_manager = state_manager.get_state_manager()
      tasks = _state_manager.get_task_data(
          instance=turbinia_config.INSTANCE_ID, request_id=request_id)

    if not summary:
      for task in tasks:
        current_request_id = task.get('request_id')
        if current_request_id == request_id:
          self.tasks.append(task)

    for task in tasks:
      self.request_id = task.get('request_id')
      self.requester = task.get('requester')
      self.reason = task.get('reason')
      self.task_count = len(tasks)
      task_status = task.get('status')
      if isinstance(task.get('last_update'), datetime.datetime):
        task_last_update = datetime.datetime.timestamp(task.get('last_update'))
      else:
        task_last_update = task.get('last_update')

      if not self.last_task_update_time:
        self.last_task_update_time = task_last_update
      else:
        self.last_task_update_time = max(
            self.last_task_update_time, task_last_update)
      if task.get('successful'):
        self.successful_tasks += 1
      # 'successful' could be None or False, which means different things.
      # If False, the task has failed, If None, could be queued or running.
      elif task.get('successful') is False:
        self.failed_tasks += 1
      elif task.get('successful') is None:
        if task_status:
          if 'running' in task_status:
            self.running_tasks += 1
        else:
          # 'successful' is None and 'status' is None
          self.queued_tasks += 1
      if isinstance(task['last_update'], datetime.datetime):
        task['last_update'] = task['last_update'].strftime(
            turbinia_config.DATETIME_FORMAT)

    if self.last_task_update_time:
      if isinstance(self.last_task_update_time, float):
        self.last_task_update_time = datetime.datetime.fromtimestamp(
            self.last_task_update_time).strftime(
                turbinia_config.DATETIME_FORMAT)

    if self.running_tasks > 0:
      self.status = 'running'
    elif self.failed_tasks == self.task_count:
      self.status = 'failed'
    elif self.successful_tasks == self.task_count:
      self.status = 'successful'
    else:
      self.status = 'completed_with_errors'

    return bool(self.tasks)


class RequestsSummary(BaseModel):
  """Represents a summary view of multiple Turbinia requests."""
  requests_status: List[RequestStatus] = []

  def get_requests_summary(self) -> bool:
    """Generates a status summary for each Turbinia request."""
    _state_manager = state_manager.get_state_manager()
    instance_id = turbinia_config.INSTANCE_ID
    tasks = _state_manager.get_task_data(instance=instance_id)
    request_ids = set()

    for task in tasks:
      request_id = task.get('request_id')
      if not request_id in request_ids:
        request_ids.add(request_id)

    for request_id in request_ids:
      filtered_tasks = [
          task for task in tasks if task.get('request_id') == request_id
      ]
      request_status = RequestStatus()
      request_status.get_request_data(request_id, filtered_tasks, summary=True)
      self.requests_status.append(request_status)

    return bool(self.requests_status)
