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
import os

from fastapi import HTTPException, APIRouter
from fastapi.responses import StreamingResponse, FileResponse
from fastapi.requests import Request

from turbinia import config as turbinia_config
from turbinia import state_manager
from turbinia.api import utils as api_utils

log = logging.getLogger('turbinia')

router = APIRouter(prefix='/result', tags=['Turbinia Request Results'])

ATTACHMENT_RESPONSE = {
    '200': {
        'content': {
            'application/octet-stream': {
                'schema': {
                    'type': 'string',
                    'format': 'binary'
                }
            }
        }
    }
}


@router.get(
    '/task/{task_id}', response_class=StreamingResponse,
    responses=ATTACHMENT_RESPONSE)
async def get_task_output(request: Request, task_id: str) -> StreamingResponse:
  """Retrieves a task's output files."""
  # Get the request_id for the task. This is needed to find the right path.
  _state_manager = state_manager.get_state_manager()
  tasks = _state_manager.get_task_data(
      instance=turbinia_config.INSTANCE_ID, task_id=task_id)
  if not tasks:
    raise HTTPException(status_code=404, detail=f'Task {task_id:s} not found.')

  request_id = tasks[0].get('request_id')
  output_path = api_utils.get_task_output_path(request_id, task_id)

  if request_id and output_path:
    return StreamingResponse(
        api_utils.create_tarball(output_path),
        headers={
          'Content-Disposition': f'attachment;filename={task_id}.tgz',
          'Transfer-Encoding': 'chunked'})
  else:
    raise HTTPException(
        status_code=404, detail='The requested file was not found.')

@router.get(
    '/request/{request_id}', response_class=StreamingResponse,
    responses=ATTACHMENT_RESPONSE)
async def get_request_output(
    request: Request, request_id: str) -> StreamingResponse:
  """Retrieve request output."""
  if not request_id:
    raise HTTPException(status_code=404, detail='Request not found.')

  request_output_path = api_utils.get_request_output_path(request_id)
  if request_output_path:
    return StreamingResponse(
        api_utils.create_tarball(request_output_path),
        headers={
          'Content-Disposition': f'attachment;filename={request_id}.tgz',
          'Transfer-Encoding': 'chunked'})
  else:
    raise HTTPException(
        status_code=404, detail='The requested file was not found.')

@router.get('/plasofile/{task_id}', response_class=FileResponse,
    responses=ATTACHMENT_RESPONSE)
async def get_plaso_file(request: Request, task_id: str) -> FileResponse:
  """Retrieves a task's Plaso file."""
  if not task_id:
    raise HTTPException(status_code=404, detail='Task identifier not provided.')

  _state_manager = state_manager.get_state_manager()
  tasks = _state_manager.get_task_data(
      instance=turbinia_config.INSTANCE_ID, task_id=task_id)
  if not tasks:
    raise HTTPException(status_code=404, detail=f'Task {task_id:s} not found.')

  filename = f'{task_id}.plaso'
  request_id = tasks[0].get('request_id')
  output_path = api_utils.get_task_output_path(request_id, task_id)
  plaso_file_path = os.path.join(output_path, filename)

  if os.path.exists(plaso_file_path):
    return FileResponse(plaso_file_path, filename=filename)
  raise HTTPException(
      status_code=404, detail=f'File {filename} could not be found.')
