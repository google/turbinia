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

from typing import Dict

from fastapi import HTTPException, APIRouter
from pydantic import ValidationError

from turbinia import state_manager
from turbinia import config as turbinia_config

from fastapi import HTTPException, APIRouter
from pydantic import ValidationError


log = logging.getLogger('turbinia:api_server:task')

router = APIRouter(prefix='/task', tags=['Turbinia Tasks'])


@router.get("/{task_id}", response_model=Dict)
async def get_task_status(task_id: str):
  """Retrieve task information."""
  try:
    _state_manager = state_manager.get_state_manager()
    tasks = _state_manager.get_task_data(
        instance=turbinia_config.INSTANCE_ID, task_id=task_id)
    task = tasks[0]
    if task:
      return task
    return HTTPException(status_code=404, detail='Task ID not found')
  except ValidationError as exception:
    log.error('Error retrieving task information: {}'.format(exception))
    raise HTTPException(
        status_code=500,
        detail='Error retrieving task information') from exception
  except Exception as exception:
    log.error('An unexpected error occurred: {}'.format(exception))
    raise HTTPException(
        status_code=500, detail='An unknown error occurred.') from exception
