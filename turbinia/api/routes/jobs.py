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
"""Turbinia API - Jobs router"""

import json
import logging

from fastapi import HTTPException, APIRouter
from fastapi.responses import JSONResponse

from turbinia import config as turbinia_config
from turbinia.jobs import manager as jobs_manager

log = logging.getLogger('turbinia:api_server:jobs')

router = APIRouter(prefix='/jobs', tags=['Turbinia Jobs'])


@router.get("/")
async def read_jobs():
  """Return enabled jobs from the current Turbinia config."""
  try:
    _jobs_manager = jobs_manager.JobsManager()
    registered_jobs = set(_jobs_manager.GetJobNames())
    disabled_jobs = set(turbinia_config.CONFIG.DISABLED_JOBS)
    enabled_jobs = registered_jobs.difference(disabled_jobs)

    if not registered_jobs:
      raise HTTPException(status_code=404, detail='No registered jobs found.')
    return JSONResponse(content=list(enabled_jobs), status_code=200)
  except (json.JSONDecodeError, TypeError) as exception:
    log.error('Error listing jobs: {0!s}'.format(exception))
    raise HTTPException(
        status_code=500, detail='error listing jobs') from exception
