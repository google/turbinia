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
from datetime import datetime
from datetime import timedelta

from fastapi import HTTPException, APIRouter
from fastapi.responses import JSONResponse
from fastapi.requests import Request
from fastapi.encoders import jsonable_encoder

from operator import itemgetter, attrgetter
from pydantic import ValidationError
from turbinia import state_manager
from turbinia import config as turbinia_config
from turbinia import client as TurbiniaClientProvider

log = logging.getLogger('turbinia:api_server:task')

router = APIRouter(prefix='/task', tags=['Turbinia Tasks'])

client = TurbiniaClientProvider.get_turbinia_client()


class WorkerStatus:
  """A json-serializable report of the workers status."""

  def __init__(self, instance: str, project: str, region: str, days: int = 7):
    """Initializes the WorkerStatus class.

    Args:
      instance (string): The Turbinia instance name (by default the same as the
          INSTANCE_ID in the config).
      project (string): The name of the project.
      region (string): The name of the zone to execute in.
      days (int): The number of days we want the report for.
    """

    self.instance = instance
    self.project = project
    self.region = region
    self.days = days
    self.workers_dict = {}
    self.unassigned_dict = {}
    self.scheduled_counter = 0

  def simplify_task_dict(self, task: dict) -> dict:
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

  def get_workers_dict(self):
    """Retrieves the general workers dict.
    
    Returns:
      task_dict (dict): A non-serializable workers status dictionary.
    """

    task_results = client.get_task_data(
        self.instance, self.project, self.region, self.days)

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

  def get_worker_status(self, all_fields: bool = False):
    """Formats the workers_dict with relevant and serializable information.
    
    Args:
      all_fields (bool): Returns all worker fields if set to true.

    Returns:
      task_dict (dict): A json-serializable and workers status dictionary.
    """

    self.get_workers_dict()

    if not self.workers_dict:
      return {}

    report = {'scheduled_tasks': self.scheduled_counter}

    for worker_node, tasks in self.workers_dict.items():
      report[worker_node] = {}
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
      report[worker_node]['run_status'] = run_status
      report[worker_node]['queued_status'] = queued_status
      # Add Finished Tasks
      if all_fields:
        report[worker_node]['other_status'] = other_status

      # Add unassigned worker tasks
      unassigned_status = {}
      for tasks in self.unassigned_dict.values():
        for task in tasks:
          unassigned_status[task['task_id']] = self.simplify_task_dict(task)
      # Now add to main report
      if all_fields:
        report[worker_node]['unassigned_status'] = unassigned_status

    return report


def format_task_statistics(
    instance, project, region, days=0, task_id=None, request_id=None,
    user=None) -> dict:
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
  workers_dict = WorkerStatus(
      instance=turbinia_config.INSTANCE_ID,
      project=turbinia_config.TURBINIA_PROJECT,
      region=turbinia_config.TURBINIA_REGION,
      days=days).get_worker_status(all_fields)
  if workers_dict:
    return JSONResponse(content=workers_dict, status_code=200)
  raise HTTPException(status_code=404, detail='No workers found.')


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
