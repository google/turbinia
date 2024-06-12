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

import logging

from typing import Optional, List, Dict
from pydantic import BaseModel
from turbinia import state_manager
from turbinia import config as turbinia_config

log = logging.getLogger(__name__)


class RequestStatus(BaseModel):
  """Represents a Turbinia request status object."""
  evidence_id: str = None
  evidence_name: str = None
  failed_tasks: int = 0
  last_task_update_time: str = None
  queued_tasks: int = 0
  reason: str = None
  request_id: str = None
  requester: str = None
  running_tasks: int = 0
  status: str = None
  successful_tasks: int = 0
  task_count: int = 0
  tasks: List[Dict] = []

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
    state_client = state_manager.get_state_manager()
    self.request_id = request_id

    if not summary:
      self.tasks = tasks if tasks else state_client.get_task_data(
          instance=turbinia_config.INSTANCE_ID, request_id=request_id)

    # Gets the information from the request if it is stored in Redis
    request_key = state_client.redis_client.build_key_name(
        'request', request_id)
    if state_client.redis_client.key_exists(request_key):
      saved_request = state_client.get_request_data(request_id)
      self.evidence_name = saved_request.get('original_evidence').get('name')
      self.evidence_id = saved_request.get('original_evidence').get('id')
      self.requester = saved_request.get('requester')
      self.reason = saved_request.get('reason')
      self.status = saved_request.get('status')
      self.last_task_update_time = saved_request.get('last_update')
      self.successful_tasks = len(saved_request.get('successful_tasks', []))
      self.failed_tasks = len(saved_request.get('failed_tasks', []))
      self.queued_tasks = len(saved_request.get('queued_tasks', []))
      self.running_tasks = len(saved_request.get('running_tasks', []))
      task_ids = saved_request.get('task_ids', [])
      self.task_count = len(task_ids)
      self.status = saved_request.get('status', 'pending')

    return bool(self.tasks)


class RequestsSummary(BaseModel):
  """Represents a summary view of multiple Turbinia requests."""
  requests_status: List[RequestStatus] = []

  def get_requests_summary(self) -> bool:
    """Generates a status summary for each Turbinia request."""
    state_client = state_manager.get_state_manager()

    for request_key in state_client.redis_client.iterate_keys('Request'):
      request_id = request_key.split(':')[1]
      request_status = RequestStatus()
      request_status.get_request_data(request_id, summary=True)
      self.requests_status.append(request_status)

    return bool(self.requests_status)
