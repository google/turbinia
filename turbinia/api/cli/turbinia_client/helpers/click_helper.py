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
"""Turbinia API client command-line tool."""

import os
import logging
import click
import base64

from typing import Tuple, Sequence
from turbinia_api_lib.api import turbinia_configuration_api
from turbinia_api_lib.api import turbinia_requests_api

from turbinia_api_lib import exceptions
from turbinia_api_lib import api_client

log = logging.getLogger(__name__)


def generate_option_parameters(
    option_name: str) -> Tuple[Tuple[Sequence[str], str], dict]:
  """Builds click.Option or click.Command arguments based on a given parameter 
      name.
  """
  return ((['--' + option_name], option_name), {'required': False, 'type': str})


@click.pass_context
def create_request(ctx: click.Context, *args: int, **kwargs: int) -> None:
  """Creates and submits a new Turbinia request."""
  client: api_client.ApiClient = ctx.obj.api_client
  api_instance = turbinia_requests_api.TurbiniaRequestsApi(client)
  evidence_name = ctx.command.name

  # Normalize the evidence class name from lowercase to the original name.
  evidence_name = ctx.obj.normalize_evidence_name(evidence_name)
  # Build request and request_options objects to send to the API server.
  request_options = list(ctx.obj.request_options.keys())
  request = {'evidence': {'type': evidence_name}, 'request_options': {}}

  if 'googlecloud' in evidence_name:
    api_instance_config = turbinia_configuration_api.TurbiniaConfigurationApi(
        client)
    cloud_provider = api_instance_config.read_config()['CLOUD_PROVIDER']
    if cloud_provider != 'GCP':
      log.error(
          f'The evidence type {evidence_name} is Google Cloud only and '
          f'the configured provider for this Turbinia instance is '
          f'{cloud_provider}.')
      return

  for key, value in kwargs.items():
    # If the value is not empty, add it to the request.
    if kwargs.get(key):
      # Check if the key is for evidence or request_options
      if not key in request_options:
        request['evidence'][key] = value
      elif key in ('jobs_allowlist', 'jobs_denylist'):
        jobs_list = value.split(',')
        request['request_options'][key] = jobs_list
      else:
        request['request_options'][key] = value

  if all(key in request['request_options']
         for key in ('recipe_name', 'recipe_data')):
    log.error('You can only provide one of recipe_data or recipe_name')
    return

  recipe_name = request['request_options'].get('recipe_name')
  if recipe_name:
    if not recipe_name.endswith('.yaml'):
      recipe_name = f'{recipe_name}.yaml'
    # Fallback path for the recipe would be TURBINIA_CLI_CONFIG_PATH/recipe_name
    # This is the same path where the client configuration is loaded from.
    recipe_path_fallback = os.path.expanduser(ctx.obj.config_path)
    recipe_path_fallback = os.path.join(recipe_path_fallback, recipe_name)

    if os.path.isfile(recipe_name):
      recipe_path = recipe_name
    elif os.path.isfile(recipe_path_fallback):
      recipe_path = recipe_path_fallback
    else:
      log.error(f'Unable to load recipe {recipe_name}.')
      return

    try:
      with open(recipe_path, 'r', encoding='utf-8') as recipe_file:
        # Read the file and convert to base64 encoded bytes.
        recipe_bytes = recipe_file.read().encode('utf-8')
        recipe_data = base64.b64encode(recipe_bytes)
    except OSError as exception:
      log.error(f'Error opening recipe file {recipe_path}: {exception}')
      return
    except TypeError as exception:
      log.error(f'Error converting recipe data to Base64: {exception}')
      return
    # We found the recipe file, so we will send it to the API server
    # via the recipe_data parameter. To do so, we need to pop recipe_name
    # from the request so that we only have recipe_data.
    request['request_options'].pop('recipe_name')
    # recipe_data should be a UTF-8 encoded string.
    request['request_options']['recipe_data'] = recipe_data.decode('utf-8')

  # Send the request to the API server.
  try:
    click.echo(f'Sending request: {request}')
    api_response = api_instance.create_request(request)
    click.echo(f'Received response: {api_response}')
  except exceptions.ApiException as exception:
    log.error(
        f'Received status code {exception.status} '
        f'when calling create_request: {exception.body}')
  except (TypeError, exceptions.ApiTypeError) as exception:
    log.error(f'The request object is invalid. {exception}')
