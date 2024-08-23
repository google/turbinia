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
import os
import tarfile
import io
import mmap

from typing import Any, AsyncGenerator, List

from fastapi import HTTPException
from turbinia import TurbiniaException
from turbinia import config as turbinia_config
from turbinia import state_manager

log = logging.getLogger(__name__)


def get_task_objects(task_id: str) -> List[Any]:
  """Returns a list of Turbinia tasks.
  
  Riases:
    HTTPException: if the specified task was not found.
  """
  _state_manager = state_manager.get_state_manager()
  tasks = _state_manager.get_task_data(
      instance=turbinia_config.INSTANCE_ID, task_id=task_id)

  if not tasks:
    raise HTTPException(status_code=404, detail=f'Task {task_id:s} not found.')
  return tasks


def get_request_output_path(request_id: str) -> str:
  """Returns the output path for a request_id."""
  log_path = turbinia_config.toDict().get('OUTPUT_DIR')
  request_output_path = os.path.join(log_path, request_id)
  if not os.path.exists(request_output_path):
    message = 'Output path {0:s} for request {1:s} could not be found.'.format(
        request_output_path, request_id)
    log.error(message)
    raise HTTPException(status_code=404, detail=message)
  return request_output_path


def get_task_output_path(request_id: str, task_id: str) -> str:
  """Returns the output path for a task_id."""
  request_output_path = get_request_output_path(request_id)
  task_output_path = request_output_path
  if task_id:
    try:
      request_dirs = os.listdir(request_output_path)
    except FileNotFoundError as exception:
      message = 'Output path {0:s} for task {1:s} could not be found.'.format(
          request_output_path, task_id)
      log.error(message)
      raise HTTPException(status_code=404, detail=message) from exception

    latest_timestamp = 0
    for task_dir in request_dirs:
      # We'll check the timestamp that's part of the directory name
      # to make sure we grab the most recent directory for the task
      # in case there are more than one.
      if task_id in task_dir:
        timestamp = int(task_dir.split('-')[0])
        if timestamp > latest_timestamp:
          latest_timestamp = timestamp
          task_output_path = os.path.join(request_output_path, task_dir)

    return task_output_path


def get_plaso_file_path(task_id: str) -> str:
  """Returns the saved_path for a specific Plaso task."""
  task = get_task_objects(task_id)[0]
  output_dir = turbinia_config.toDict().get('OUTPUT_DIR')

  if not task or not task.get('name').startswith('Plaso'):
    raise TurbiniaException(f'Task {task_id} not found or is not a Plaso task.')

  for saved_path in task.get('saved_paths'):
    if saved_path.startswith(output_dir) and saved_path.endswith('.plaso'):
      return saved_path


class ByteStream:
  """A writeable in-memory stream used to create tgz files."""

  def __init__(self):
    """Initialize the object."""
    self.buffer = io.BytesIO()
    self.block_size = 4194304  # 4 MiB
    self.offset = 0

  def __enter__(self):
    return self

  def __exit__(self, exc_type, exc_value, traceback):
    del exc_type, exc_value, traceback  # Unused.
    self.close()

  def write(self, data):
    """Writes data to the buffer and adjusts offset."""
    self.buffer.write(data)
    self.offset += len(data)

  def tell(self):
    """Returns the current byte offset."""
    return self.offset

  def close(self):
    """Closes the buffer."""
    self.buffer.close()

  def pop(self):
    """Returns the bytes from the buffer.

    Seeks buffer to position 0 and truncates the buffer for re-use.
    """
    data = self.buffer.getvalue()
    self.buffer.seek(0)
    self.buffer.truncate()
    return data


async def create_tarball(output_path: str) -> AsyncGenerator[bytes, Any]:
  """Creates an in-memory TGZ file from output_path contents.

  Partially inspired by the StreamingTarGenerator class from Google's GRR.

  Reference:
      https://github.com/google/grr/blob/master/grr/core/grr_response_core/lib/utils.py

  Args:
    output_path (str): The output path of a request or task to archive.

  Yields:
    bytes: tgz file chunk.
  """
  file_paths = []
  for root, _, filenames in os.walk(output_path):
    for filename in filenames:
      file_path = os.path.join(root, filename)
      # skip empty files
      if os.stat(file_path).st_size > 0:
        file_paths.append(file_path)

  with ByteStream() as stream:
    with tarfile.TarFile.open(fileobj=stream, mode='w:gz',
                              compresslevel=1) as tar:
      for file_path in file_paths:
        log.info(f'Adding {file_path} to tarball.')
        tar_info = tar.gettarinfo(name=file_path)
        tar.addfile(tar_info)
        # Yield the header for the tarinfo file.
        yield stream.pop()

        with open(file_path, 'rb') as in_fp:
          # Read the input file in chunks of stream.block_size bytes.
          while True:
            data = in_fp.read(stream.block_size)
            if len(data) > 0:
              # Write the data to the buffer.
              tar.fileobj.write(data)
              # Yield a compressed file chunk so the client can receive it.
              yield stream.pop()
            # Write padding if necessary.
            if len(data) < stream.block_size:
              blocks, remainder = divmod(tar_info.size, tarfile.BLOCKSIZE)
              if remainder > 0:
                tar.fileobj.write(tarfile.NUL * (tarfile.BLOCKSIZE - remainder))
                yield stream.pop()
                blocks += 1
              tar.offset += blocks * tarfile.BLOCKSIZE
              break

    # Yield end-of-archive marker.
    yield stream.pop()


def tail_log(log_path, max_lines=500) -> str:
  """Reads a log file and returns the last max_lines."""
  if not os.path.isfile(log_path):
    return ''

  nlines = 0
  log_lines: bytes = b''

  with open(log_path, 'r', encoding='utf-8') as file:
    try:
      with mmap.mmap(file.fileno(), 0, prot=mmap.PROT_READ) as memfile:
        pos = len(memfile)
        while (nlines <= max_lines and pos > -1):
          pos -= 1
          if memfile[pos:pos + 1] == '\n'.encode():
            nlines += 1
        log_lines = memfile[pos + 1:]

      return log_lines.decode('utf-8')
    except ValueError as exception:
      raise TurbiniaException(
          f'Error decoding log line: {exception}') from exception
