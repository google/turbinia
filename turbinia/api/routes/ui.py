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
"""Turbinia Web UI routes."""

import os
import pathlib
from fastapi import APIRouter, HTTPException
from fastapi.requests import Request
from fastapi.responses import RedirectResponse, FileResponse
from turbinia import config

ui_router = APIRouter(tags=['Turbinia Web UI'])
_config = config.LoadConfig()


@ui_router.get('/', include_in_schema=False)
async def root():
  """Default route."""
  return RedirectResponse('/web')


@ui_router.get('/web', name='web', include_in_schema=False)
async def web(request: Request):
  """Serves the Web UI main page."""
  static_content_path = pathlib.Path(
      _config.WEBUI_PATH).joinpath('dist/index.html')
  if os.path.exists(static_content_path):
    response = FileResponse(
        path=static_content_path, headers={'Cache-Control': 'no-cache'})
    return response

  raise HTTPException(status_code=404, detail='Not found')


@ui_router.get(
    '/assets/{catchall:path}', name='assets', include_in_schema=False)
async def serve_assets(request: Request):
  """Serves assets content."""
  web_root_path = pathlib.Path(_config.WEBUI_PATH).joinpath('dist/assets')
  requested_path = request.path_params['catchall']
  absolute_path = web_root_path.joinpath(requested_path).resolve()
  if os.path.exists(absolute_path) and absolute_path.is_relative_to(
      web_root_path) and absolute_path.is_file():
    return FileResponse(absolute_path)

  raise HTTPException(status_code=404, detail='Not found')
