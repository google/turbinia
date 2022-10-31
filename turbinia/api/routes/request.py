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
from turbinia.lib import recipe_helpers
from turbinia.api.schemas import request
from turbinia.api.models import request_status

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
    if not requests_summary.get_requests_summary():
      return JSONResponse(
          content={'detail': 'Request summary is empty'}, status_code=200)
    return requests_summary
  except (ValidationError, ValueError, TypeError) as exception:
    log.error(
        'Error retrieving requests summary: {0!s}'.format(exception),
        exc_info=True)
    raise HTTPException(
        status_code=500,
        detail='Error retrieving requests summary') from exception


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
    log.error('Error retrieving request information: {0!s}'.format(exception))
    raise HTTPException(
        status_code=500,
        detail='Error retrieving request information') from exception


@router.post("/")
async def create_request(req: request.Request):
  """Create a new Turbinia request.

  Args:
    request (turbinia.api.schema.request): JSON object from the HTTP POST data
        matching the schema defined for a Turbinia Request. The schema is used
        by pydantic for field validation.

  Raises:
    ValidationError: if the Request object contains invalid data.
    HTTPException: If pre-conditions are not met.
  """
  client = turbinia_client.get_turbinia_client()
  evidence_list = []
  request_id = req.request_id
  group_id = req.group_id
  requester = req.requester
  reason = req.reason
  recipe = None
  recipe_name = req.request_options.recipe_name
  recipe_data = req.request_options.recipe_data
  options = req.request_options

  if not request_id:
    request_id = uuid.uuid4().hex

  if not group_id:
    group_id = uuid.uuid4().hex

  try:
    if recipe_data and recipe_name:
      raise HTTPException(
          status_code=400,
          detail='You can only provide one of recipe_data or recipe_name.')

    if recipe_data:
      # Use a client-provided recipe. recipe_data MUST be a Base64 encoded
      # YAML representation of a Turbinia recipe. The recipe will be validated.
      # We assume that if the client provided a custom recipe it will include
      # its own jobs_allowlist, filter_patterns and other settings.
      recipe = recipe_helpers.load_recipe_from_data(recipe_data)
    elif recipe_name:
      # Use a client-provided recipe name or path for an existing recipe.
      recipe = client.create_recipe(
          group_id=group_id, recipe_name=recipe_name,
          sketch_id=req.request_options.sketch_id)
    elif (options.jobs_allowlist or options.jobs_denylist or
          options.filter_patterns or options.yara_rules):
      recipe = client.create_recipe(
          group_id=group_id, jobs_allowlist=options.jobs_allowlist,
          jobs_denylist=options.jobs_denylist,
          filter_patterns=options.filter_patterns,
          yara_rules=options.yara_rules, sketch_id=options.sketch_id)
    # Create an appropriate evidence.Evidence object based on the
    # "type" attribute from the evidence object.
    # The following is an example of what a POST request might look like:
    # pylint: disable=pointless-string-statement
    """
    {
      "description": "Turbinia request object",
      "evidence": { 
        "_name": "Rawdisk evidence", 
        "source_path": "/root/evidence.dd", 
        "type": "RawDisk"
        },
      "request_options": {
        "sketch_id": 1234,
        "recipe_name": "triage-linux"
      },
      "reason": "test",
      "requester": "tester"
    }
    ----
    {
      "description": "Turbinia request object",
      "evidence": { 
      "_name": "Rawdisk evidence", 
      "source_path": "/root/evidence.dd", 
      "type": "RawDisk"
      },
      "request_options": {
      "sketch_id": 1234,
      "recipe_data": "Z2xvYmFsczoKICBqb2JzX2FsbG93bGlzdDoKICAgIC0gQ3JvbkV4dHJhY3Rpb25Kb2IKICAgIC0gQ3JvbkFuYWx5c2lzSm9iCiAgICAtIFBsYXNvSm9iCiAgICAtIFBzb3J0Sm9iCiAgICAtIEZpbGVTeXN0ZW1UaW1lbGluZUpvYgoKcGxhc29fYmFzZToKICB0YXNrOiAnUGxhc29UYXNrJwoKICBhcnRpZmFjdF9maWx0ZXJzOiBbCiAgICAnQWxsVXNlcnNTaGVsbEhpc3RvcnknLAogICAgJ0FwYWNoZUFjY2Vzc0xvZ3MnLAogICAgJ0Jyb3dzZXJDYWNoZScsCiAgICAnQnJvd3Nlckhpc3RvcnknLAogICAgJ0Nocm9tZVN0b3JhZ2UnLAogICAgJ0xpbnV4QXVkaXRMb2dzJywKICAgICdMaW51eEF1dGhMb2dzJywKICAgICdMaW51eENyb25Mb2dzJywKICAgICdMaW51eEtlcm5lbExvZ0ZpbGVzJywKICAgICdMaW51eExhc3Rsb2dGaWxlJywKICAgICdMaW51eE1lc3NhZ2VzTG9nRmlsZXMnLAogICAgJ0xpbnV4U2NoZWR1bGVGaWxlcycsCiAgICAnTGludXhTeXNMb2dGaWxlcycsCiAgICAnTGludXhVdG1wRmlsZXMnLAogICAgJ0xpbnV4V3RtcCcsCiAgXQ=="
      },
      "reason": "test",
      "requester": "tester"
    }
    """
    evidence_object = evidence.evidence_decode(req.evidence, strict=True)
    if not evidence_object:
      raise HTTPException(
          status_code=400,
          detail='Error creating evidence object from {0!s}'.format(
              req.evidence))
    evidence_list.append(evidence_object)
    # If at this point the recipe is None, the TurbiniaClient will create
    # a generic recipe based on recipe_helpers.DEFAULT_RECIPE.
    request_out = client.create_request(
        evidence_=evidence_list, request_id=request_id, reason=reason,
        recipe=recipe, group_id=group_id, requester=requester)
    # Send the Turbinia request to the appropriate queue.
    client.send_request(request_out)
  except TurbiniaException as exception:
    log.error('Error creating new Turbinia request: {0!s}'.format(exception))
    raise HTTPException(
        status_code=400,
        detail='Error creating new Turbinia request: {0!s}'.format(
            exception)) from exception

  response = {'request_id': request_out.request_id}
  return JSONResponse(content=response, status_code=200)
