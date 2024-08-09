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
from fastapi import HTTPException, APIRouter, UploadFile, Query, Form
from fastapi.requests import Request
from fastapi.responses import JSONResponse, FileResponse
from typing import List, Annotated

from turbinia import evidence
from turbinia import config as turbinia_config
from turbinia import state_manager
from turbinia import TurbiniaException

log = logging.getLogger(__name__)
router = APIRouter(prefix='/evidence', tags=['Turbinia Evidence'])
redis_manager = state_manager.RedisStateManager()

EVIDENCE_SUMMARY_ATTRIBUTES = (
    '_name', 'cloud_only', 'context_dependent', 'copyable', 'creation_time',
    'description', 'has_child_evidence', 'last_update', 'local_path',
    'mount_path', 'parent_evidence', 'request_id', 'resource_id',
    'resource_tracked', 'save_metadata', 'saved_path', 'saved_path_type',
    'size', 'source', 'source_path', 'type')

EVIDENCE_QUERY_ATTRIBUTES = EVIDENCE_SUMMARY_ATTRIBUTES + ('tasks',)


async def get_file_path(file_name: str, ticket_id: str) -> str:
  """Gets the path where the file will be saved.

  Args:
    file_name (str): Original name of the file.
    ticked_id (str): ID of the current ticket
  
  Returns:
    file_path (str): Path where the file will be saved.
  """
  try:
    file_name_without_ext, file_extension = os.path.splitext(file_name)
    current_time = datetime.now().strftime(turbinia_config.DATETIME_FORMAT)
    new_name = f'{file_name_without_ext}_{current_time}{file_extension}'
    os.makedirs(
        f'{turbinia_config.API_EVIDENCE_UPLOAD_DIR}/{ticket_id}', exist_ok=True)
    return os.path.join(
        turbinia_config.API_EVIDENCE_UPLOAD_DIR, ticket_id, new_name)
  except OSError as exception:
    raise TurbiniaException(
        f'Failed in setting path for file {file_name} in ticket '
        f'{ticket_id}') from exception


async def upload_file(
    file: UploadFile, file_path: str, calculate_hash: bool = False) -> dict:
  """Uploads file from FastAPI to server.

  Args:
    file (UploadFile): Evidence file to be uploaded to folder for later
        processing. The maximum size of the file is set on the Turbinia
        configuration file. 
    file_path (str): Path where the file will be saved.
    calculate_hash (bool): Boolean defining if the hash of the evidence should
      be calculated.
  
  Raises:
    IOError: If file is greater than the maximum size.
  
  Returns:
    file_info (dict): Information about the uploaded file.
  """
  size = 0
  sha_hash = hashlib.sha3_224()
  with open(file_path, 'wb') as saved_file:
    while (chunk := await
           file.read(turbinia_config.API_UPLOAD_CHUNK_SIZE
                    )) and size < turbinia_config.API_MAX_UPLOAD_SIZE:
      saved_file.write(chunk)
      if calculate_hash:
        sha_hash.update(chunk)
      size += len(chunk)
      if size >= turbinia_config.API_MAX_UPLOAD_SIZE:
        msg_size = turbinia_config.API_MAX_UPLOAD_SIZE / (1024**3)
        error_message = (
            f'Unable to upload file {file.filename} greater',
            f'than {msg_size} GB')
        log.error(error_message)
        raise TurbiniaException(error_message)
    file_info = {
        'original_name': file.filename,
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
  """Returns supported required parameters for evidence type.
  
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
    request: Request, group: str = Query(
        None, enum=EVIDENCE_SUMMARY_ATTRIBUTES), output: str = Query(
            'keys', enum=('keys', 'content', 'count'))):
  """Retrieves a summary of all evidences in Redis.

  Args:
    group Optional(str): Attribute used to group summary.
    output Optional(str): Sets how the evidence found will be output. 

  Returns:
    summary (dict): Summary of all evidences and their content.
  
  Raises:
    HTTPException: if there are no evidences.
  """
  if group and group not in EVIDENCE_SUMMARY_ATTRIBUTES:
    raise HTTPException(
        status_code=400, detail=(
            f'Cannot group by attribute {group}. '
            f'Groupable attributes: {EVIDENCE_SUMMARY_ATTRIBUTES}'))
  if evidences := redis_manager.get_evidence_summary(group, output):
    return JSONResponse(content=evidences, status_code=200)
  raise HTTPException(status_code=404, detail='No evidence found.')


@router.get('/query')
async def query_evidence(
    request: Request, attribute_name: str = Query(
        'request_id', enum=EVIDENCE_QUERY_ATTRIBUTES),
    attribute_value: str = Query(), output: str = Query(
        'keys', enum=('keys', 'content', 'count'))):
  """Queries evidence in Redis that have the specified attribute value.

  Args:
    attribute_name (str): Name of attribute to be queried.
    attribute_value (str): Value the attribute must have.
    output Optional(str): Sets how the evidence found will be output.

  Returns:
    summary (dict): Summary of all evidences and their content.
  
  Raises:
    HTTPException: If no matching evidence is found.
  """
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
  """Retrieves an evidence in Redis by using its UUID.

  Args:
    evidence_id (str): The UUID of the evidence.
  
  Raises:
    HTTPException: if the evidence is not found.

  Returns:
    Dictionary of the stored evidence
  """
  if stored_evidence := redis_manager.get_evidence_data(evidence_id):
    return JSONResponse(content=stored_evidence, status_code=200)
  raise HTTPException(
      status_code=404,
      detail=f'UUID {evidence_id} not found or it had no associated evidence.')


@router.post('/upload')
async def upload_evidence(
    ticket_id: Annotated[str, Form()], files: List[UploadFile],
    calculate_hash: Annotated[bool, Form()] = False):
  """Upload evidence file to server for processing.

  Args:
    ticket_id (str): ID of the ticket, which will be the name of the folder 
      where the evidence will be saved.
    calculate_hash (bool): Boolean defining if the hash of the evidence should
      be calculated.
    file (List[UploadFile]): Evidence files to be uploaded to folder for later
        processing. The maximum size of the file is 10 GB. 
  
  Returns:
    List of uploaded evidences or warning messages if any.
  """
  evidences = []
  for file in files:
    warning_message = None
    try:
      file_path = await get_file_path(file.filename, ticket_id)
      file_info = await upload_file(file, file_path, calculate_hash)
      file.file.close()
    except TurbiniaException as exception:
      warning_message = exception
    else:
      if evidence_key := redis_manager.get_evidence_key_by_hash(
          file_info.get('hash')):
        warning_message = (
            f'File {file.filename} was uploaded before, check {evidence_key}')

    if warning_message:
      evidences.append(warning_message)
      log.error(warning_message)
      try:
        file_path = await get_file_path(file.filename, ticket_id)
        os.remove(file_path)
      except OSError as exception:
        log.error(f'Could not remove file {file_path}: {exception}')
    else:
      evidences.append(file_info)
  return JSONResponse(content=evidences, status_code=200)


@router.get('/download/{evidence_id}', response_class=FileResponse)
async def download_by_evidence_id(
    request: Request, evidence_id) -> FileResponse:
  """Downloads an evidence file based in its UUID.

  Args:
    evidence_id (str): The UUID of the evidence.
  
  Raises:
    HTTPException: if the evidence is not found.

  Returns:
    FileResponse: The evidence file.
  """
  evidence_key = redis_manager.redis_client.build_key_name(
      'evidence', evidence_id)
  if redis_manager.redis_client.key_exists(evidence_key):
    data: dict = redis_manager.get_evidence_data(evidence_id)
    file_path: str = None
    if not data['copyable']:
      raise HTTPException(status_code=400, detail='Evidence is not copyable.')
    if data['source_path']:
      file_path = data['source_path']
    elif data['local_path']:
      file_path = data['local_path']

    if file_path and os.path.exists(file_path):
      filename = os.path.basename(file_path)
      return FileResponse(file_path, filename=filename)
  raise HTTPException(
      status_code=404,
      detail=f'UUID {evidence_id} not found or it had no associated evidence.')
