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
"""Turbinia API - Download router"""

import logging
import pathlib

from fastapi import HTTPException, APIRouter
from fastapi.responses import FileResponse
from fastapi.requests import Request

from turbinia import config as turbinia_config

log = logging.getLogger(__name__)
router = APIRouter(prefix='/download', tags=['Turbinia Download'])


@router.get('/output/{file_path:path}', response_class=FileResponse)
async def download_output_path(
    request: Request, file_path: str) -> FileResponse:
  """Downloads output file path.
  
  Args:
    file_path (str): Path to file.
  """

  # clean path to prevent path traversals
  # check if path is below the configured output folder
  # check if exists and is file
  config_output_dir = pathlib.Path(turbinia_config.OUTPUT_DIR)
  requested_file = pathlib.Path(file_path).resolve()
  if requested_file.is_relative_to(
      config_output_dir) and requested_file.is_file():
    return FileResponse(requested_file, media_type='application/octet-stream')

  raise HTTPException(
      status_code=404, detail='Access denied or file not found!')
