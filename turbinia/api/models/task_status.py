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
"""Turbinia API server task status model."""

import datetime
import json
import logging

from typing import Optional, List, Union, Dict
from pydantic import BaseModel
from turbinia import state_manager

log = logging.getLogger('turbinia:api_server')


class TaskStatus(BaseModel):
  """Represents a Turbinia TaskStatus object."""
  description: Optional[str] = 'Turbinia Task Status'
  id: str = None
  last_update: datetime.datetime = None
  name: str = None
  worker_name: str = None
  report_data: str = None
  report_priority: int = None
  request_id: str = None
  run_time: Union[datetime.timedelta, None] = None
  status: str = None
  saved_paths: List[str] = None
  successful: bool = None
  instance: str = None

  def get_task_data_json(self, serialized_task: Dict):
    """Update the attributes from a JSON serialized task.

    Args:
      serialized_task (Dict): A JSON object representing a Turbinia task.
    """
    self.__dict__.update(serialized_task)

  def get_task_data_redis(self, task_id: str):
    """Gets task information from Redis and sets object attributes.

    Args:
      task_id (str): A Turbinia task identifier.

    Returns:
      bool: True if the task was found and has a task name.
    """
    _state_manager = state_manager.get_state_manager()
    client = _state_manager.client

    with client:
      task_data = client.get("TurbiniaTask:{}".format(task_id))
      if task_data:
        try:
          task_json = json.loads(task_data)
          self.id = task_json.get('id')
          self.last_update = task_json.get('last_update')
          self.name = task_json.get('name')
          self.worker_name = task_json.get('worker_name')
          self.report_data = task_json.get('report_data')
          self.report_priority = task_json.get('report_priority')
          self.run_time = task_json.get('run_time')
          self.request_id = task_json.get('request_id')
          self.status = task_json.get('status')
          self.saved_paths = task_json.get('saved_paths')
          self.instance = task_json.get('instance')
          self.successful = task_json.get('successful')
        except json.JSONDecodeError as exception:
          log.error('Error reading task data from Redis: {}'.format(exception))

    return bool(self.name)