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

from fastapi import HTTPException, APIRouter, UploadFile, File
from fastapi.requests import Request
from fastapi.responses import JSONResponse
from typing import List

from turbinia.api.schemas import request_options
from turbinia.api.schemas import evidence as api_evidence
from turbinia import evidence
from turbinia import config as turbinia_config
from turbinia import state_manager

log = logging.getLogger('turbinia')
router = APIRouter(prefix='/evidence', tags=['Turbinia Evidence'])
redis_manager = state_manager.RedisStateManager()


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
async def get_evidence_summary(request: Request):
  """Retrieves a summary of all evidences in redis.
  
  Raises:
    HTTPException: if there are no evidences.
  """
  evidences = redis_manager.get_evidence_summary()
  if evidences:
    return JSONResponse(
        content=redis_manager.get_evidence_summary(), status_code=200)
  raise HTTPException(status_code=404, detail='No evidences found.')


@router.get('/id')
async def get_evidence_by_id(request: Request, evidence_id):
  """Retrieves an evidence in redis by using its UUID.

  Args:
    evidence_id (str): The UUID of the evidence.
  
  Raises:
    HTTPException: if the evidence is not found.

  Returns:

  """
  if redis_manager.get_evidence(evidence_id):
    return JSONResponse(
        content=redis_manager.get_evidence(evidence_id), status_code=200)
  raise HTTPException(
      status_code=404,
      detail=f'UUID {evidence_id} not found or it had no associated evidences.')


@router.get('/{hash}')
async def get_evidence_by_hash(request: Request, file_hash):
  """Retrieves an evidence in redis by using its hash (SHA3-224).

  Args:
    file_hash (str): SHA3-224 hash of file.
  
  Raises:
    HTTPException: if the evidence is not found.

  Returns:

  """
  if redis_manager.get_evidence_by_hash(file_hash):
    return JSONResponse(
        content=redis_manager.get_evidence_by_hash(file_hash), status_code=200)
  raise HTTPException(
      status_code=404,
      detail=f'Hash {file_hash} not found or it had no associated evidences.')


#todo(igormr) update request_ids for every request
#todo(igormr) Make TurbiniaRequest on redis pointing to TurbiniaEvidence and back
#todo(igormr) Add
#todo(igormr) Use something else other than the hash as the key


@router.post('/upload')
async def upload_evidence(
    request: Request, information: List[api_evidence.Evidence],
    files: List[UploadFile] = File(...)):
  """Upload evidence file to server for processing.

  Args:
    file (List[UploadFile]): Evidence file to be uploaded to folder for later
        processing. The maximum size of the file is 10 GB. 
    information (List[Evidence]): The information about each of the files
        uploaded. The attributes "file_name" and "evidence_type" are mandatory
        for all evidences, the other attributes are necessary depending on the 
        evidence type. Check /api/evidence/types for more info.
  
  Raises:
    TypeError: If pre-conditions are not met.
  
  Returns:
    List of uploaded evidences or warning messages if any.
  """
  # Extracts nested dict
  information = information[0]
  evidences = []
  separator = '' if turbinia_config.OUTPUT_DIR[-1] == '/' else '/'
  for file in files:
    file_info = information.get(file.filename, None)
    if not file_info:
      warning_message = f'No information found for file {file.filename}'
      evidences.append(warning_message)
      log.error(warning_message)
    else:
      name = file_info.new_name
      file_path = separator.join([turbinia_config.OUTPUT_DIR, name])
      equal_files = 1
      while os.path.exists(file_path):
        equal_files += 1
        name = f'({equal_files}) {file_info.new_name}'
        file_path = separator.join([turbinia_config.OUTPUT_DIR, name])
      sha_hash = hashlib.sha3_224()
      size = 0
      warning_message = None
      with open(file_path, 'wb') as saved_file:
        while (chunk := await file.read(1024)) and size < 10737418240:
          saved_file.write(chunk)
          sha_hash.update(chunk)
          size += 1024
          if size >= 10737418240:
            warning_message = ', '.join(
                (f'Unable to upload file {file.filename} greater than 10 GB'))
      file.file.close()
      file_hash = sha_hash.hexdigest()
      if evidence_ := redis_manager.get_evidence_by_hash(file_hash):
        warning_message = (
            f'File {file.filename} was uploaded before, check {evidence_[0]}')
      if warning_message:
        evidences.append(warning_message)
        log.error(warning_message)
        try:
          os.remove(file_path)
        except OSError:
          log.error(f'Could not remove file {file_path}')
      else:
        evidence_ = evidence.create_evidence(
            evidence_type=file_info.evidence_type.lower(),
            source_path=file_path, browser_type=file_info.browser_type,
            disk_name=file_info.disk_name,
            embedded_path=file_info.embedded_path, format=file_info.format,
            mount_partition=file_info.mount_partition, name=file_info.name,
            profile=file_info.profile, project=file_info.project,
            source=file_info.source, zone=file_info.zone, file_hash=file_hash)
        evidences.append(evidence_.serialize())
  return JSONResponse(content=evidences, status_code=200)
