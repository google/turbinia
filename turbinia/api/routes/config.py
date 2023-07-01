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

import json
import logging
import os
import hashlib

from fastapi import HTTPException, APIRouter, UploadFile, Query
from fastapi.responses import JSONResponse
from fastapi.requests import Request
from typing import List

from turbinia import config as turbinia_config
from turbinia import evidence
from turbinia.api.schemas import request_options
from turbinia import client as TurbiniaClientProvider

log = logging.getLogger('turbinia')

router = APIRouter(prefix='/config', tags=['Turbinia Configuration'])

client = TurbiniaClientProvider.get_turbinia_client()


@router.get('/')
async def read_config(request: Request):
  """Retrieve turbinia config."""
  try:
    current_config = turbinia_config.toDict()
    if current_config:
      return JSONResponse(content=current_config, status_code=200)
  except (json.JSONDecodeError, TypeError) as exception:
    log.error(f'Error reading configuration: {exception!s}')
    raise HTTPException(
        status_code=500, detail='error reading configuration') from exception


@router.get('/evidence')
async def get_evidence_types(request: Request):
  """Returns supported Evidence object types and required parameters."""
  attribute_mapping = evidence.map_evidence_attributes()
  return JSONResponse(content=attribute_mapping, status_code=200)


from pydantic import BaseModel


class UploadedEvidence(UploadFile, BaseModel):
  """Base request object. """

  names: str = Query(None)
  evidence_types: str = Query(None)


#todo(igormr) add max file length
#todo(igormr) store saved files in redis (TurbiniaEvidence) and evidencecollection
# request id
# evidence type
# fastapi model class for parameters
#use getdisksize below
#handle errors with delete
#use fast hash, probably hash() or sha256
# Make TurbiniaRequest on redis pointing to TurbiniaEvidence and back
#make a python object and serialize it before storing in redis
#use validate to check if the type makes sense
@router.post('/evidence/upload')
async def upload_evidence(
    request: Request, evidence: List[List[str, UploadedEvidence]]) -> None:
  """Upload evidence file to the /evidence/ folder for processing.
  Args:
    file: Evidence file to be uploaded to evidences folder for later
        processing. The maximum size of the file is 10 GB. 
    name: The name with which the file will be saved. It is necessary to
        include the extension of the file. The name cannot be equal to that
        of an existent file.
    evidence_type: The type of the 
  Raises:
    HTTPException: If pre-conditions are not met.
  """
  if len(files) != len(names) or len(files) != len(evidence_types):
    log.error(f'Wrong number of arguments: {TypeError}')
    raise TypeError('Wrong number of arguments')
  files_information = []
  separator = '' if turbinia_config.OUTPUT_DIR[-1] == '/' else '/'
  for i in range(len(files)):
    name = names[i]
    file_path = separator.join([turbinia_config.OUTPUT_DIR, name])
    equal_files = 1
    while os.path.exists(file_path):
      equal_files += 1
      name = f'({equal_files})' + names[i]
      file_path = separator.join([turbinia_config.OUTPUT_DIR, name])
    with open(file_path, 'wb') as saved_file:
      md5_hash = hashlib.md5()
      while chunk := await files[i].read(1024):
        saved_file.write(chunk)
        md5_hash.update(chunk)
      file_hash = md5_hash.hexdigest()
    files[i].file.close()
    if client.redis.get_evidence(file_hash):
      os.remove(file_path)
      message = {(
          f'File {names[i]} was uploaded before,\n' +
          f'check TurbiniaEvidence:{file_hash}')}
      files_information.append(message)
      log.error(message)
    else:
      files_information.append({
          'name': name,
          'path': file_path,
          'evidence_type': evidence_types[i],
          'size': os.stat(file_path).st_size,
          'hash': file_hash
      })
      client.redis.write_new_evidence(files_information[i])
  return files_information


@router.get('/evidence/{hash}')
async def get_request_status(file_hash: str):
  """Retrieves status for a Turbinia Request.
  Args:
    request_id (str): A Turbinia request identifier.
  Raises:
    HTTPException: if another exception is caught.
  """
  if client.redis.get_evidence(file_hash):
    return client.redis.get_evidence(file_hash)
  else:
    raise HTTPException(
        status_code=404,
        detail='Request ID not found or the request had no associated tasks.')


@router.get('/evidence/{evidence_name}')
async def get_evidence_attributes_by_name(request: Request, evidence_name):
  """Returns supported Evidence object types and required parameters."""
  attribute_mapping = evidence.map_evidence_attributes()
  attribute_mapping = {evidence_name: attribute_mapping.get(evidence_name)}
  if not attribute_mapping:
    raise HTTPException(
        status_code=404, detail=f'Evidence type ({evidence_name:s}) not found.')
  return JSONResponse(content=attribute_mapping, status_code=200)


@router.get('/request_options')
async def get_request_options(request: Request):
  """Returns a list BaseRequestOptions attributes."""
  attributes = request_options.BaseRequestOptions.__annotations__
  attributes_dict = {}
  for attribute_name, attribute_type in attributes.items():
    attributes_dict[attribute_name] = {'type': str(attribute_type)}
  return JSONResponse(content=attributes_dict, status_code=200)
