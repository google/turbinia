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
"""Turbinia API Server helper methods."""

import logging
import mmap
import shutil
import tempfile
import os

from fastapi import HTTPException
from turbinia import config as turbinia_config

log = logging.getLogger('turbinia:api_server:utils')


def create_zip(request_id: str, task_id: str):
  """Compress a Turbinia request or task's output directories into a zip file.

  Args:
    request_id (str): Turbinia request identifier.
    task_id (str): Turbinia task identifier.

  Returns:
    A zip compressed bytes stream

  Raises:
    HTTPException if the request/task output paths could not be found
        on the file system.
  """
  log_path = turbinia_config.toDict().get('OUTPUT_DIR')

  request_output_path = os.path.join(log_path, request_id)

  if task_id:
    try:
      request_dirs = os.listdir(request_output_path)
    except FileNotFoundError as exception:
      message = 'Output path {0:s} for task {1:s} could not be found.'.format(
          request_output_path, task_id)
      log.error(message)
      raise HTTPException(status_code=404, detail=message) from exception

    for request_dir in request_dirs:
      if task_id in request_dir:
        request_output_path = os.path.join(request_output_path, request_dir)
        break

  if not os.path.exists(request_output_path):
    message = 'Output path {0:s} for request {1:s} could not be found.'.format(
        request_output_path, request_id)
    log.error(message)
    raise HTTPException(status_code=404, detail=message)

  # Create a temporary directory to store the zip file
  # containing the request result files.
  # Directory and its contents deleted upon context exit.
  temp_directory = tempfile.TemporaryDirectory()
  with temp_directory as directory_name:
    if task_id:
      zip_path = os.path.join(directory_name, task_id)
    else:
      zip_path = os.path.join(directory_name, request_id)

    # Create the zip file
    zip_filename = shutil.make_archive(zip_path, 'zip', request_output_path)
    data = None

    # Read the zip using a memory-mapped file and return it
    with open(zip_filename, 'rb') as zip_obj:
      mm = mmap.mmap(zip_obj.fileno(), 0, access=mmap.ACCESS_READ)
      data = mm.read()

    return data
