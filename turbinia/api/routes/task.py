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
from fastapi.responses import JSONResponse, PlainTextResponse
from fastapi.requests import Request
from fastapi.encoders import jsonable_encoder

from pydantic import ValidationError
from turbinia import config as turbinia_config
from turbinia import state_manager
from turbinia.api.models import workers_status
from turbinia.api.models import tasks_statistics
from turbinia.api.models import request_status
from turbinia.api.cli.turbinia_client.helpers.formatter import TaskMarkdownReport

log = logging.getLogger(__name__)

router = APIRouter(prefix='/task', tags=['Turbinia Tasks'])


@router.get('/statistics')
async def get_task_statistics(
    request: Request, days: int = None, task_id: str = None,
    request_id: str = None,
    user: str = None) -> tasks_statistics.CompleteTurbiniaStats:
  """Retrieves  statistics for Turbinia execution.

  Args:
    days (int): The number of days we want history for.
    task_id (string): The Id of the task.
    request_id (string): The Id of the request we want tasks for.
    user (string): The user of the request we want tasks for.

  Returns:
    statistics (str): JSON-formatted task statistics report.
  """
  statistics = tasks_statistics.CompleteTurbiniaStats()
  if statistics.format_task_statistics(days=days, task_id=task_id,
                                       request_id=request_id, user=user):
    return statistics
  raise HTTPException(status_code=404, detail='No task found.')


@router.get('/workers')
async def get_workers_status(
    request: Request, days: int = 7, all_fields: bool = False):
  """Retrieves the workers status.

  Args:
    days (int): The UUID of the evidence.
    all_fields (bool): Returns all status fields if set to true.

  Returns:
    workers_status (str): JSON-formatted workers status.

  Raises:
    HTTPException: if no worker is found.
  """
  workers_dict = workers_status.WorkersStatus()
  if workers_dict.get_workers_status(days, all_fields):
    return JSONResponse(content=workers_dict.status, status_code=200)
  raise HTTPException(status_code=404, detail='No workers found.')


@router.get('/{task_id}')
async def get_task_status(request: Request, task_id: str):
  """Retrieve task information."""
  try:
    state_client = state_manager.get_state_manager()
    tasks = state_client.get_task_data(
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


@router.get('/report/{task_id}')
async def get_task_report(request: Request, task_id: str):
  """Retrieves the MarkDown report of a Turbinia task.

  Raises:
    HTTPException: if another exception is caught.
  """
  try:
    task_data = state_manager.get_state_manager().get_task(task_id=task_id)
    if not task_data:
      raise HTTPException(status_code=404, detail='Task not found.')
    markdownreport = TaskMarkdownReport(
        request_data=task_data).generate_markdown()

    return PlainTextResponse(content=markdownreport, status_code=200)
  except (json.JSONDecodeError, TypeError, ValueError, AttributeError,
          ValidationError) as exception:
    log.error(f'Error retrieving markdown report: {exception!s}', exc_info=True)
    raise HTTPException(
        status_code=500,
        detail='Error retrieving markdown report') from exception
