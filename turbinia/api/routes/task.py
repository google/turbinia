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
"""Turbinia API - Task router"""

import logging
import json

from collections import OrderedDict

from fastapi import HTTPException, APIRouter
from fastapi.responses import JSONResponse
from fastapi.requests import Request
from fastapi.encoders import jsonable_encoder

from operator import attrgetter
from pydantic import ValidationError
from turbinia import state_manager
from turbinia import config as turbinia_config
from turbinia import client as TurbiniaClientProvider
from turbinia.api.models import workers_status

log = logging.getLogger('turbinia:api_server:task')

router = APIRouter(prefix='/task', tags=['Turbinia Tasks'])

client = TurbiniaClientProvider.get_turbinia_client()


def format_task_statistics(
    instance: str, project: str, region: str, days: int = 0,
    task_id: str = None, request_id: str = None, user: str = None) -> dict:
  """Formats statistics for Turbinia execution data as a json-serializable dict.

    Args:
      instance (string): The Turbinia instance name (by default the same as the
          INSTANCE_ID in the config).
      project (string): The name of the project.
      region (string): The name of the zone to execute in.
      days (int): The number of days we want history for.
      task_id (string): The Id of the task.
      request_id (string): The Id of the request we want tasks for.
      user (string): The user of the request we want tasks for.

    Returns:
      report (dict): Task statistics report.
    """
  task_stats = client.get_task_statistics(
      instance, project, region, days, task_id, request_id, user)

  report = {}
  if not task_stats:
    return report

  stats_order = [
      'all_tasks', 'successful_tasks', 'failed_tasks', 'requests',
      'tasks_per_type', 'tasks_per_worker', 'tasks_per_user'
  ]
  for stat_name in stats_order:
    report[stat_name] = {}
    stat_obj = task_stats[stat_name]
    if isinstance(stat_obj, dict):
      # Sort by description so that we get consistent report output
      inner_stat_objs = sorted(stat_obj.values(), key=attrgetter('description'))
      for inner_stat_obj in inner_stat_objs:
        if stat_name == 'tasks_per_worker':
          description = inner_stat_obj.description.replace('Worker ', '', 1)
        elif stat_name == 'tasks_per_user':
          description = inner_stat_obj.description.replace('User ', '', 1)
        else:
          description = inner_stat_obj.description.replace('Task type ', '', 1)
        report[stat_name][description] = inner_stat_obj.to_dict()
      continue
    report[stat_name] = stat_obj.to_dict()

  return report


@router.get('/statistics')
async def get_task_statistics(
    request: Request, days: int = None, task_id: str = None,
    request_id: str = None, user: str = None):
  """Retrieves  statistics for Turbinia execution.

  Args:
    days (int): The number of days we want history for.
    task_id (string): The Id of the task.
    request_id (string): The Id of the request we want tasks for.
    user (string): The user of the request we want tasks for.

  Returns:
    statistics (dict): Task statistics report.
  """
  statistics = format_task_statistics(
      instance=turbinia_config.INSTANCE_ID,
      project=turbinia_config.TURBINIA_PROJECT,
      region=turbinia_config.TURBINIA_REGION, days=days, task_id=task_id,
      request_id=request_id, user=user)
  if statistics:
    return JSONResponse(content=statistics, status_code=200)
  raise HTTPException(status_code=404, detail='No task found.')


@router.get('/workers')
async def get_workers_status(
    request: Request, days: int = 7, all_fields: bool = False):
  """Retrieves the workers status.

  Args:
    days (int): The UUID of the evidence.
  
  Raises:
    HTTPException: if no worker is found.
  Returns:
  """
  workers_dict = workers_status.WorkersStatus()
  if workers_dict.get_workers_status(days, all_fields):
    return JSONResponse(content=workers_dict.status, status_code=200)
  raise HTTPException(status_code=404, detail='No workers found.')


@router.get('/{task_id}')
async def get_task_status(request: Request, task_id: str):
  """Retrieve task information."""
  try:
    _state_manager = state_manager.get_state_manager()
    tasks = _state_manager.get_task_data(
        instance=turbinia_config.INSTANCE_ID, task_id=task_id)
    if tasks:
      task = tasks[0]
      task_json = jsonable_encoder(task)
      task_json_sorted = OrderedDict(sorted(task_json.items()))
      return JSONResponse(
          status_code=200, content=task_json_sorted,
          media_type='application/json')
    raise HTTPException(status_code=404, detail='Task ID not found.')
  except (json.JSONDecodeError, TypeError, ValueError,
          ValidationError) as exception:
    log.error(f'Error retrieving task information: {exception!s}')
    raise HTTPException(
        status_code=500,
        detail='Error retrieving task information') from exception
