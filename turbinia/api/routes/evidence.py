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
    return redis_manager.get_evidence_summary()
  raise HTTPException(status_code=404, detail='No evidences found.')


@router.get('/{file_hash}')
async def get_evidence_by_hash(request: Request, file_hash):
  """Retrieves an evidence in redis by using its hash (SHA3-224).

  Args:
    file_hash (str): SHA3-224 hash of file.
  
  Raises:
    HTTPException: if the evidence is not found.
  """
  if redis_manager.get_evidence(file_hash):
    return redis_manager.get_evidence(file_hash)
  else:
    raise HTTPException(
        status_code=404,
        detail=f'Hash {file_hash} not found or it had no associated evidences.')


#todo(igormr) add max file length
#todo(igormr) update request_ids for every request
#todo(igormr) Make TurbiniaRequest on redis pointing to TurbiniaEvidence and back


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
  """
  # Extracts nested dict
  information = information[0]
  evidences = []
  separator = '' if turbinia_config.TMP_DIR[-1] == '/' else '/'
  for file in files:
    file_info = information.get(file.filename, None)
    if not file_info:
      message = f'No information found for file {file.filename}'
      evidences.append(message)
      log.error(message)
    else:
      name = file_info.new_name
      file_path = separator.join([turbinia_config.TMP_DIR, name])
      equal_files = 1
      while os.path.exists(file_path):
        equal_files += 1
        name = f'(({equal_files}) {file_info.new_name})'
        file_path = separator.join([turbinia_config.TMP_DIR, name])
      with open(file_path, 'wb') as saved_file:
        sha_hash = hashlib.sha3_224()
        while chunk := await file.read(1024):
          saved_file.write(chunk)
          sha_hash.update(chunk)
        file_hash = sha_hash.hexdigest()
      file.file.close()
      if redis_manager.get_evidence(file_hash):
        message = ', '.join((
            f'File {file.filename} was uploaded before',
            f'check TurbiniaEvidence:{file_hash}'))
        evidences.append(message)
        log.error(message)
        try:
          os.remove(file_path)
        except OSError:
          log.error(f'Could not remove duplicate file {file_path}')
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
  return evidences
