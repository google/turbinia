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
"""Turbinia API - Result router"""

import logging

from fastapi import HTTPException, APIRouter
from fastapi.responses import Response
from turbinia import config as turbinia_config
from turbinia import state_manager
from turbinia.api import utils as api_utils

log = logging.getLogger('turbinia:api_server:result')

router = APIRouter(prefix='/result', tags=['Turbinia Request Results'])

_ATTACHMENT_RESPONSE = {'200': {'content': {'application/x-zip-compressed'}}}


@router.get(
    "/task/{task_id}", response_class=Response, responses=_ATTACHMENT_RESPONSE)
async def get_task_output(task_id: str):
  """Retrieves a task's output files."""
  # Get the request_id for the task. This is needed to find the right path.
  data = None
  _state_manager = state_manager.get_state_manager()
  tasks = _state_manager.get_task_data(
      instance=turbinia_config.INSTANCE_ID, task_id=task_id)
  if not tasks:
    raise HTTPException(
        status_code=404, detail='Task {0:s} not found.'.format(task_id))
  request_id = tasks[0].get('request_id')
  if request_id:
    data = api_utils.create_zip(request_id, task_id)

  if not data:
    raise HTTPException(
        status_code=500, detail='Unable to retrieve task output files.')
  return Response(
      data, media_type='application/x-zip-compressed', headers={
          "Content-Disposition": 'attachment;filename={}.zip'.format(task_id)
      })


@router.get(
    "/request/{request_id}", response_class=Response,
    responses=_ATTACHMENT_RESPONSE)
async def get_request_output(request_id: str):
  """Retrieve request output."""
  data = api_utils.create_zip(request_id, task_id=None)

  if not data:
    raise HTTPException(
        status_code=500, detail='Unable to retrieve task output files.')
  return Response(
      data, media_type='application/x-zip-compressed', headers={
          "Content-Disposition":
              'attachment;filename={}.zip'.format(request_id)
      })
