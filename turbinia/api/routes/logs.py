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
"""Turbinia API - Logs router"""

import logging

from fastapi import APIRouter
from fastapi.responses import JSONResponse
from fastapi.requests import Request

log = logging.getLogger(__name__)

router = APIRouter(prefix='/logs', tags=['Turbinia Logs'])


@router.get('/{query}')
async def get_logs(request: Request, query: str):
  """Retrieve log data."""
  return JSONResponse(
      content={'detail': 'Not implemented yet.'}, status_code=200)
