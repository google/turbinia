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
import os

from pathlib import Path

from fastapi import APIRouter, Query
from fastapi.responses import JSONResponse, PlainTextResponse
from fastapi.requests import Request
from turbinia import config, TurbiniaException
from turbinia.api import utils

log = logging.getLogger(__name__)

router = APIRouter(prefix='/logs', tags=['Turbinia Logs'])


@router.get('/server')
async def get_server_logs(
    request: Request, num_lines: int | None = Query(default=500, gt=0)
) -> PlainTextResponse:
  """Retrieve log data."""
  return JSONResponse(
      content={'detail': 'Not implemented yet.'}, status_code=200)


@router.get('/api_server')
async def get_api_server_logs(
    request: Request, num_lines: int | None = Query(default=500, gt=0)
) -> PlainTextResponse:
  """Retrieve log data."""
  hostname = os.uname().nodename
  log_name = f'{hostname}.log'
  log_path = Path(config.LOG_DIR, log_name)
  log_lines = utils.tail_log(log_path, num_lines)
  if log_path:
    return PlainTextResponse(log_lines)
  return JSONResponse(
      content={'detail': f'No logs found for {hostname}'}, status_code=404)


@router.get('/{hostname}')
async def get_turbinia_logs(
    request: Request, hostname: str, num_lines: int | None = Query(
        default=500, gt=0)
) -> PlainTextResponse:
  """Retrieve log data.
  
  Turbinia currently stores logs on plaintext files. The log files are named
  <hostname>.log for each instance of a worker, server or API server.

  In some deployments, the same file can contain all logs (e.g. running all
  services locally in the same container).
  """
  if not hostname:
    return JSONResponse(content={'detail': 'Invalid hostname'}, status_code=404)

  if 'NODE_NAME' in os.environ:
    log_name = f'{hostname}.{os.environ["NODE_NAME"]!s}.log'
  else:
    log_name = f'{hostname}.log'
  log_path = Path(config.LOG_DIR, log_name)
  try:
    log_lines = utils.tail_log(log_path, num_lines)
    if log_lines:
      return PlainTextResponse(log_lines)
  except TurbiniaException:
    return JSONResponse(
        content={'detail': 'Error reading log data.'}, status_code=500)

  return JSONResponse(
      content={'detail': f'No logs found for {hostname}'}, status_code=404)
