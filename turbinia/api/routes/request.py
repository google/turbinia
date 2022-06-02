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
"""Turbinia API - Request router"""

import logging
import uuid

from fastapi import HTTPException, APIRouter
from fastapi.responses import JSONResponse

from pydantic import ValidationError
from turbinia import TurbiniaException, client as turbinia_client
from turbinia import evidence
from turbinia.api.schemas import evidence_types
from turbinia.api.schemas import request
from turbinia.api.models import request_status
from pydantic import ValidationError
from turbinia import TurbiniaException, client as turbinia_client
from turbinia import evidence

log = logging.getLogger('turbinia:api_server:models:request')
router = APIRouter(prefix="/request", tags=["Turbinia Requests"])


@router.get("/summary", response_model=request_status.RequestsSummary)
async def get_requests_summary():
  """Retrieves a summary of all Turbinia requests.

  The response is validated against the RequestSummary model.

  Raises:
    HTTPException: if another exception is caught.
  """
  requests_summary = request_status.RequestsSummary()
  try:
    if not requests_summary.get_requests_summmary():
      raise HTTPException(
          status_code=500, detail='Unable to generate requests status summary.')
    return requests_summary
  except (ValidationError, ValueError, TypeError) as exception:
    log.error('Error retrieving requests summary: {}'.format(exception))
    raise HTTPException(
        status_code=500,
        detail='Error retrieving requests summary') from exception
  except Exception as exception:
    log.error('An unexpected error occurred: {}'.format(exception))
    raise HTTPException(
        status_code=500, detail='An unknown error occurred.') from exception


@router.get("/{request_id}", response_model=request_status.RequestStatus)
async def get_request_status(request_id: str):
  """Retrieves status for a Turbinia Request.

  Args:
    request_id (str): A Turbinia request identifier.

  Raises:
    HTTPException: if another exception is caught.
  """
  request_out = request_status.RequestStatus(request_id=request_id)
  response_ok = request_out.get_request_data(request_id)
  try:
    if not response_ok:
      raise HTTPException(
          status_code=404,
          detail='Request ID not found or the request had no associated tasks.')
    return request_out
  except (ValidationError, ValueError, TypeError) as exception:
    log.error('Error retrieving request information: {}'.format(exception))
    raise HTTPException(
        status_code=500,
        detail='Error retrieving request information') from exception


@router.post("/")
async def create_request(input_request: request.Request):
  """Create a new Turbinia request.
  
  Args:
    request (turbinia.api.schema.request): JSON object from the HTTP POST data
        matching the schema defined for a Turbinia Request. The schema is used
        by pydantic for field validation.

  Raises:
    ValidationError: if the Request object contains invalid data.
  """
  client = turbinia_client.get_turbinia_client()
  evidence_list = []
  request_id = request.request_id
  group_id = request.group_id
  recipe = None

  try:
    if input_request.evidence_type == evidence_types.EvidenceTypesEnum.rawdisk:
      rawdisk = evidence.RawDisk(
          source_path=input_request.evidence_options.source_path)
      rawdisk.validate()
      evidence_list.append(rawdisk)
    elif input_request.evidence_type == (
        evidence_types.EvidenceTypesEnum.compresseddirectory):
      directory = evidence.CompressedDirectory(
          source_path=input_request.evidence_options.source_path)
      directory.validate()
      evidence_list.append(directory)
    elif input_request.evidence_type == (
        evidence_types.EvidenceTypesEnum.directory):
      directory = evidence.Directory(
          name='directory',
          source_path=input_request.evidence_options.source_path)
      evidence_list.append(directory)
    elif input_request.evidence_type == (
        evidence_types.EvidenceTypesEnum.googleclouddisk):
      gcp_disk = input_request.GoogleCloudDisk(
          name='gcp_disk', disk_name=input_request.evidence_options.disk_name,
          project=input_request.evidence_options.project,
          zone=input_request.evidence_options.zone)
      evidence_list.append(gcp_disk)
    elif input_request.evidence_type == (
        evidence_types.EvidenceTypesEnum.googleclouddiskembedded):
      parent_disk = input_request.GoogleCloudDisk(
          name='parent gcp disk',
          disk_name=input_request.evidence_options.disk_name,
          project=input_request.evidence_options.project,
          mount_partition=input_request.evidence_options.mount_partition,
          zone=input_request.evidence_options.zone)
      gcp_disk = evidence.GoogleCloudDiskRawEmbedded(
          name='gcp disk', disk_name=input_request.evidence_options.disk_name,
          project=input_request.evidence_options.project,
          zone=input_request.evidence_options.zone,
          embedded_path=input_request.evidence_options.embedded_path)
      gcp_disk.set_parent(parent_disk)
      evidence_list.append(gcp_disk)
    else:
      raise HTTPException(
          status_code=400, detail='An unsupported evidence type was provided.')

    if not request_id:
      request_id = uuid.uuid4().hex

    if not group_id:
      group_id = uuid.uuid4().hex

    if input_request.evidence_options.turbinia_recipe:
      recipe_name = input_request.evidence_options.turbinia_recipe

    recipe = client.create_recipe(
        group_id=group_id, recipe_name=recipe_name,
        filter_patterns=input_request.evidence_options.filter_patterns,
        yara_rules=input_request.evidence_options.filter_patterns,
        sketch_id=request.sketch_id)
    if request.job_options.turbinia_recipe:
      recipe = client.create_recipe(
          recipe_name=request.job_options.turbinia_recipe)

    request_out = client.create_request(
        evidence_=evidence_list, request_id=request_id, recipe=recipe,
        group_id=group_id, requester='test')

    client.send_request(request_out)

  except TurbiniaException as exception:
    log.error('Error creating new Turbinia request: {}'.format(exception))
    raise HTTPException(
        status_code=400,
        detail='Error creating new Turbinia request: {}'.format(
            exception)) from exception

  response = {'request_id': request_out.request_id}
  return JSONResponse(content=response, status_code=200)
