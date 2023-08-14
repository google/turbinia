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

from fastapi import HTTPException, APIRouter, Query
from fastapi.responses import JSONResponse
from fastapi.requests import Request
from fastapi.encoders import jsonable_encoder

from operator import itemgetter
from pydantic import ValidationError
from turbinia import state_manager
from turbinia import config as turbinia_config
from turbinia import client as TurbiniaClientProvider

log = logging.getLogger('turbinia:api_server:task')

router = APIRouter(prefix='/task', tags=['Turbinia Tasks'])

client = TurbiniaClientProvider.get_turbinia_client()


def worker_status(instance, project, region, days=0):
  # Set number of days to retrieve data
  num_days = days if days != 0 else 7

  task_results = client.get_task_data(instance, project, region, days=num_days)
  if not task_results:
    return ''

  # Sort task_results by last updated timestamp.
  task_results = sorted(
      task_results, key=itemgetter('last_update'), reverse=True)

  # Create dictionary of worker_node: {{task_id, task_update,
  # task_name, task_status}}
  workers_dict = {}
  unassigned_dict = {}
  scheduled_counter = 0
  for result in task_results:
    worker_node = result.get('worker_name')
    status = result.get('status')
    status = status if status else 'No task status'
    if worker_node and worker_node not in workers_dict:
      workers_dict[worker_node] = []
    elif not worker_node:
      # Track scheduled/unassigned Tasks for reporting.
      scheduled_counter += 1
      worker_node = 'Unassigned'
      if worker_node not in unassigned_dict:
        unassigned_dict[worker_node] = []
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
        unassigned_dict[worker_node].append(task_dict)
      else:
        workers_dict[worker_node].append(task_dict)

  return workers_dict


@router.get('/workers')
async def get_workers_status(
    request: Request, days: int = Query(...), all_fields=Query(
        False, enum=(False, True))):
  """Retrieves an evidence in redis by using its UUID.
  Args:
    evidence_id (str): The UUID of the evidence.
  
  Raises:
    HTTPException: if the evidence is not found.
  Returns:
  """
  workers_dict = worker_status(
      instance=turbinia_config.INSTANCE_ID,
      project=turbinia_config.TURBINIA_PROJECT,
      region=turbinia_config.TURBINIA_REGION, days=days)
  if workers_dict:
    return JSONResponse(content=workers_dict, status_code=200)
  raise HTTPException(status_code=404, detail=f'No worker status found.')


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
