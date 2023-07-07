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

from fastapi import HTTPException, APIRouter, UploadFile, Query, File, Depends, Form
from fastapi.responses import JSONResponse
from fastapi.requests import Request
from typing import List, Dict, Union

from turbinia import config as turbinia_config
from turbinia import evidence
from turbinia.api.schemas import request_options
from turbinia import client as TurbiniaClientProvider

from pydantic import BaseModel, validator
from typing import Optional

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


class EvidenceInformation(BaseModel):
  """Base information object"""
  name: str
  evidence_type: str
  browser_type: Optional[str] = None
  disk_name: Optional[str] = None
  embedded_path: Optional[str] = None
  format: Optional[str] = None
  mount_partition: Optional[str] = None
  name: Optional[str] = None
  profile: Optional[str] = None
  project: Optional[str] = None
  source: Optional[str] = None
  zone: Optional[str] = None

  @classmethod
  def __get_validators__(cls):
    yield cls.validate_to_json

  @classmethod
  def validate_to_json(cls, value):
    if isinstance(value, str):
      entries = value.split('},')
      value = []
      for entry in entries:
        if entry[-1] != '}':
          entry = entry + '}'
        value.append(cls(**json.loads(entry)))
    return value

  @validator('evidence_type')
  @classmethod
  def check_storage_type(cls, value):
    if value not in (evidence.map_evidence_attributes().keys()):
      raise ValueError(f'{value:s} is not an evidence type.')
    return value


#todo(igormr) add max file length
#todo(igormr) store evidencecollection in redis
#todo(igormr) update request_ids for every request
#todo(igormr) Make TurbiniaRequest on redis pointing to TurbiniaEvidence and back


@router.post('/evidence/upload')
async def upload_evidence(
    request: Request, information: List[EvidenceInformation],
    files: List[UploadFile] = File(...)):
  """Upload evidence file to the OUTPUT_DIR folder for processing.
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
  # Extracts nested list
  if information:
    information = information[0]
  if len(files) != len(information):
    log.error(f'Wrong number of arguments: {TypeError}')
    raise TypeError('Wrong number of arguments')
  evidences = {}
  separator = '' if turbinia_config.OUTPUT_DIR[-1] == '/' else '/'
  for i in range(len(files)):
    name = information[i].name
    file_path = separator.join([turbinia_config.OUTPUT_DIR, name])
    equal_files = 1
    while os.path.exists(file_path):
      equal_files += 1
      name = f'({equal_files})' + information[i].name
      file_path = separator.join([turbinia_config.OUTPUT_DIR, name])
    with open(file_path, 'wb') as saved_file:
      sha_hash = hashlib.sha3_256()
      while chunk := await files[i].read(1024):
        saved_file.write(chunk)
        sha_hash.update(chunk)
      file_hash = sha_hash.hexdigest()
    files[i].file.close()
    if client.redis.get_evidence(file_hash):
      message = {
          ' '.join([
              f'File {information[i].name} was uploaded before',
              f'check TurbiniaEvidence:{file_hash}'
          ])
      }
      evidences[f'TurbiniaEvidence:{file_hash}'] = message
      log.error(message)
      try:
        os.remove(file_path)
      except OSError:
        log.error(f'Could not remove duplicate file {file_path}')
    else:
      evidence_ = evidence.create_evidence(
          evidence_type=information[i].evidence_type.lower(),
          source_path=file_path, browser_type=information[i].browser_type,
          disk_name=information[i].disk_name,
          embedded_path=information[i].embedded_path,
          format=information[i].format,
          mount_partition=information[i].mount_partition,
          name=information[i].name, profile=information[i].profile,
          project=information[i].project, source=information[i].source,
          zone=information[i].zone, file_hash=file_hash)
      key = client.redis.write_new_evidence(evidence_)
      evidences[key] = evidence_.serialize()
  return evidences


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
