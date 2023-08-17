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
"""Turbinia API - Config router"""

import hashlib
import logging
import os

from datetime import datetime
from fastapi import HTTPException, APIRouter, UploadFile, File, Query, Form
from fastapi.requests import Request
from fastapi.responses import JSONResponse
from typing import List, Annotated

from turbinia.api.schemas import request_options
from turbinia import evidence
from turbinia import config as turbinia_config
from turbinia import state_manager

log = logging.getLogger('turbinia')
router = APIRouter(prefix='/evidence', tags=['Turbinia Evidence'])
redis_manager = state_manager.RedisStateManager()

EVIDENCE_SUMMARY_ATTRIBUTES = (
    '_name', 'cloud_only', 'context_dependent', 'copyable', 'creation_time',
    'description', 'has_child_evidence', 'last_updated', 'local_path',
    'mount_path', 'parent_evidence', 'request_id', 'resource_id',
    'resource_tracked', 'save_metadata', 'saved_path', 'saved_path_type',
    'size', 'source', 'source_path', 'tasks', 'type', 'creation_time')

EVIDENCE_QUERY_ATTRIBUTES = EVIDENCE_SUMMARY_ATTRIBUTES + ('tasks',)


async def upload_file(
    file: UploadFile, file_path: str, calculate_hash: bool = False):
  """Upload file from FastAPI to server.

  Args:
    file (List[UploadFile]): Evidence file to be uploaded to folder for later
        processing. The maximum size of the file is set on the Turbinia
        configuration file. 
  
  Raises:
    IOError: If file is greater than the maximum size.
  
  Returns:
    List of uploaded evidences or warning messages if any.
  """
  size = 0
  sha_hash = hashlib.sha3_224()
  with open(file_path, 'wb') as saved_file:
    while (chunk := await file.read(
        turbinia_config.CHUNK_SIZE)) and size < turbinia_config.MAX_UPLOAD_SIZE:
      saved_file.write(chunk)
      if calculate_hash:
        sha_hash.update(chunk)
      size += turbinia_config.CHUNK_SIZE
      if size >= turbinia_config.MAX_UPLOAD_SIZE:
        error_message = (
            f'Unable to upload file {file.filename} greater',
            f'than {turbinia_config.MAX_UPLOAD_SIZE / (1024 ** 3)} GB')
        log.error(error_message)
        raise IOError(error_message)
    file_info = {
        'uploaded_name': file.filename,
        'file_name': os.path.basename(file_path),
        'file_path': file_path,
        'size': size
    }
    if calculate_hash:
      file_info['hash'] = sha_hash.hexdigest()
  return file_info


@router.get('/types')
async def get_evidence_types(request: Request):
  """Returns supported Evidence object types and required parameters."""
  attribute_mapping = evidence.map_evidence_attributes()
  return JSONResponse(content=attribute_mapping, status_code=200)


@router.get('/types/{evidence_type}')
async def get_evidence_attributes(request: Request, evidence_type):
  """Returns supported Evidence object types and required parameters.
  
  Args:
    evidence_type (str): Name of evidence type.
  """
  attribute_mapping = evidence.map_evidence_attributes()
  attribute_mapping = {evidence_type: attribute_mapping.get(evidence_type)}
  if not attribute_mapping:
    raise HTTPException(
        status_code=404, detail=f'Evidence type ({evidence_type:s}) not found.')
  return JSONResponse(content=attribute_mapping, status_code=200)


@router.get('/summary')
async def get_evidence_summary(
    request: Request, sort: str = Query(None, enum=EVIDENCE_SUMMARY_ATTRIBUTES),
    output: str = Query('keys', enum=('keys', 'values', 'count'))):
  """Retrieves a summary of all evidences in redis.

  Args:
    sort Optional(str): Attribute used to sort summary.

  Returns:
    summary (dict): Summary of all evidences and their content.
  
  Raises:
    HTTPException: if there are no evidences.
  """
  if sort and sort not in EVIDENCE_SUMMARY_ATTRIBUTES:
    raise HTTPException(
        status_code=400, detail=(
            f'Cannot sort by attribute {sort}. '
            f'Sortable attributes: {EVIDENCE_SUMMARY_ATTRIBUTES}'))
  if evidences := redis_manager.get_evidence_summary(sort, output):
    return JSONResponse(content=evidences, status_code=200)
  raise HTTPException(status_code=404, detail='No evidences found.')


@router.get('/query')
async def query_evidence(
    request: Request, attribute_name: str = Query(
        'request_id', enum=EVIDENCE_QUERY_ATTRIBUTES),
    attribute_value: str = Query(), output: str = Query(
        'keys', enum=('keys', 'values', 'count'))):
  if attribute_name and attribute_name not in EVIDENCE_QUERY_ATTRIBUTES:
    raise HTTPException(
        status_code=400, detail=(
            f'Cannot query by {attribute_name}. '
            f'Queryable attributes: {EVIDENCE_QUERY_ATTRIBUTES}'))
  evidences_found = None
  if attribute_value == 'hash':
    evidences_found = redis_manager.get_evidence_key_by_hash(attribute_name)
  else:
    evidences_found = redis_manager.query_evidence(
        attribute_name, attribute_value, output)
  if evidences_found:
    return JSONResponse(content=evidences_found, status_code=200)
  raise HTTPException(
      status_code=404, detail=(
          f'No evidence found with value {attribute_value} in attribute '
          f'{attribute_name}.'))


@router.get('/{evidence_id}')
async def get_evidence_by_id(request: Request, evidence_id):
  """Retrieves an evidence in redis by using its UUID.

  Args:
    evidence_id (str): The UUID of the evidence.
  
  Raises:
    HTTPException: if the evidence is not found.

  Returns:

  """
  if stored_evidence := redis_manager.get_evidence(evidence_id):
    return JSONResponse(content=stored_evidence, status_code=200)
  raise HTTPException(
      status_code=404,
      detail=f'UUID {evidence_id} not found or it had no associated evidences.')


#todo(igormr): Check if turbinia client works with new endpoints, especially upload


@router.post('/upload')
async def upload_evidence(
    #ticket_id: Annotated[str, Form()], calculate_hash: Annotated[bool,
    #                                                             Form()],
    # files: UploadFile(bytes)):
    files: UploadFile = File(...)):
  """Upload evidence file to server for processing.

  Args:
    file (List[UploadFile]): Evidence file to be uploaded to folder for later
        processing. The maximum size of the file is 10 GB. 
  
  Raises:
    TypeError: If pre-conditions are not met.
  
  Returns:
    List of uploaded evidences or warning messages if any.
  """
  ticket_id = 123456
  calculate_hash = False
  evidences = []
  files = [files]
  for file in files:
    file_name = os.path.splitext(file.filename)[0]
    file_extension = os.path.splitext(file.filename)[1]
    os.makedirs(f'{turbinia_config.OUTPUT_DIR}/{ticket_id}', exist_ok=True)
    file_path = (
        f'{turbinia_config.OUTPUT_DIR}/{ticket_id}/{file_name}_'
        f'{datetime.now().strftime(turbinia_config.DATETIME_FORMAT)}'
        f'{file_extension}')
    warning_message = None
    try:
      file_info = await upload_file(file, file_path, calculate_hash)
    except IOError as exception:
      warning_message = exception
    file.file.close()
    if evidence_key := redis_manager.get_evidence_key_by_hash(
        file_info.get('hash')):
      warning_message = (
          f'File {file.filename} was uploaded before, check {evidence_key}')
    if warning_message:
      evidences.append(warning_message)
      log.error(warning_message)
      try:
        os.remove(file_path)
      except OSError:
        log.error(f'Could not remove file {file_path}')
    else:
      evidences.append(file_info)
    #todo(igormr): maybe save generic evidence to pass to server
  return JSONResponse(content=evidences, status_code=200)
