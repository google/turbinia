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
"""Turbinia API client / management tool."""

import os
import logging
import json
import click
import base64

from turbinia_api_client import exceptions
from turbinia_api_client import api_client
from turbinia_api_client.api import turbinia_requests_api
from turbinia_api_client.api import turbinia_tasks_api
from turbinia_api_client.api import turbinia_configuration_api
from turbinia_api_client.api import turbinia_jobs_api
from turbinia_api_client.api import turbinia_request_results_api

from turbinia_api_client.cli.core import groups
from turbinia_api_client.cli.helpers import formatter

_LOGGER_FORMAT = '%(asctime)s %(levelname)s %(name)s - %(message)s'
logging.basicConfig(format=_LOGGER_FORMAT)
log = logging.getLogger('turbiniamgmt:core:commands')
log.setLevel(logging.DEBUG)


@groups.config_group.command('list')
@click.pass_context
def get_config(ctx: click.Context) -> None:
  """Gets Turbinia server configuration."""
  client: api_client.ApiClient = ctx.obj.api_client
  api_instance = turbinia_configuration_api.TurbiniaConfigurationApi(client)
  try:
    api_response = api_instance.read_config()
    click.echo(json.dumps(api_response))
  except exceptions.ApiException as exception:
    log.error(
        'Received status code %s when calling get_config: %s', exception.status,
        exception.body)


@groups.result_group.command('request')
@click.pass_context
@click.argument('request_id')
def get_request_result(ctx: click.Context, request_id: str) -> None:
  """Gets Turbinia request results / output files."""
  client: api_client.ApiClient = ctx.obj.api_client
  api_instance = turbinia_request_results_api.TurbiniaRequestResultsApi(client)
  try:
    api_response = api_instance.get_request_output(request_id)
    filename = api_response.name.split('/')[-1]
    click.echo(
        f'Saving request output for request {request_id:s} to: {filename:s}')
    with open(filename, 'wb') as file:
      file.write(api_response.read())
  except exceptions.ApiException as exception:
    log.error(
        'Received status code %s when calling get_request_result: %s',
        exception.status, exception.body)
  except OSError as exception:
    log.error('Unable to save file: %s', exception)


@groups.result_group.command('task')
@click.pass_context
@click.argument('task_id')
def get_task_result(ctx: click.Context, task_id: str) -> None:
  """Gets Turbinia task results / output files."""
  client: api_client.ApiClient = ctx.obj.api_client
  api_instance = turbinia_request_results_api.TurbiniaRequestResultsApi(client)
  try:
    api_response = api_instance.get_task_output(
        task_id, _check_return_type=False)
    filename = api_response.name.split('/')[-1]
    click.echo(
        f'Saving task output for request {task_id:s} to file: {filename:s}')
    with open(filename, 'wb') as file:
      file.write(api_response.read())
  except exceptions.ApiException as exception:
    log.error(
        'Received status code %s when calling get_task_result: %s',
        exception.status, exception.body)
  except OSError as exception:
    log.error('Unable to save file: %s', exception)


@groups.jobs_group.command('list')
@click.pass_context
def get_jobs(ctx: click.Context) -> None:
  """Gets Turbinia jobs list."""
  client: api_client.ApiClient = ctx.obj.api_client
  api_instance = turbinia_jobs_api.TurbiniaJobsApi(client)
  try:
    api_response = api_instance.read_jobs()
    click.echo(json.dumps(api_response))
  except exceptions.ApiException as exception:
    log.error(
        'Received status code %s when calling get_jobs: %s', exception.status,
        exception.body)


@groups.status_group.command('request')
@click.pass_context
@click.argument('request_id')
@click.option(
    '--json_dump', '-j', help='Generates JSON output.', is_flag=True,
    required=False)
def get_request(ctx: click.Context, request_id: str, json_dump: bool) -> None:
  """Gets Turbinia request status."""
  client: api_client.ApiClient = ctx.obj.api_client
  api_instance = turbinia_requests_api.TurbiniaRequestsApi(client)
  try:
    api_response = api_instance.get_request_status(request_id)
    if json_dump:
      click.echo(json.dumps(api_response))
    else:
      report = formatter.RequestMarkdownReport(api_response).generate_markdown()
      click.echo(report)
  except exceptions.ApiException as exception:
    log.error(
        'Received status code %s when calling get_request: %s',
        exception.status, exception.body)


@groups.status_group.command('summary')
@click.pass_context
@click.option(
    '--json_dump', '-j', help='Generates JSON output.', is_flag=True,
    required=False)
def get_requests_summary(ctx: click.Context, json_dump: bool) -> None:
  """Gets a summary of all Turbinia requests."""
  client: api_client.ApiClient = ctx.obj.api_client
  api_instance = turbinia_requests_api.TurbiniaRequestsApi(client)
  try:
    api_response = api_instance.get_requests_summary()
    if json_dump:
      click.echo(json.dumps(api_response))
    else:
      report = formatter.SummaryMarkdownReport(api_response).generate_markdown()
      click.echo(report)
  except exceptions.ApiException as exception:
    log.error(
        'Received status code %s when calling get_requests_summary: %s',
        exception.status, exception.body)


@groups.status_group.command('task')
@click.pass_context
@click.argument('task_id')
@click.option(
    '--json_dump', '-j', help='Generates JSON output.', is_flag=True,
    required=False)
def get_task(ctx: click.Context, task_id: str, json_dump: bool) -> None:
  """Gets Turbinia task status."""
  client: api_client.ApiClient = ctx.obj.api_client
  api_instance = turbinia_tasks_api.TurbiniaTasksApi(client)
  try:
    api_response = api_instance.get_task_status(task_id)
    if json_dump:
      click.echo(json.dumps(api_response))
    else:
      report = formatter.TaskMarkdownReport(api_response).generate_markdown()
      click.echo(report)
  except exceptions.ApiException as exception:
    log.error(
        'Received status code %s when calling get_task: %s', exception.status,
        exception.body)


@click.pass_context
def create_request(ctx: click.Context, *args: int, **kwargs: int) -> None:
  """Creates and submits a new Turbinia request."""
  client: api_client.ApiClient = ctx.obj.api_client
  api_instance = turbinia_requests_api.TurbiniaRequestsApi(client)
  evidence_name = ctx.command.name
  request_options = list(ctx.obj.request_options.keys())
  request = {'evidence': {'type': evidence_name}, 'request_options': {}}

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
  if recipe_name and os.path.isfile(recipe_name):
    with open(recipe_name, 'r', encoding='utf-8') as recipe_file:
      # Read the file and convert to base64 encoded bytes.
      recipe_bytes = recipe_file.read().encode('utf-8')
      recipe_data = base64.b64encode(recipe_bytes)
      # We found the recipe file, so we will send it to the API server
      # via the recipe_data parameter. To do so, we need to pop recipe_name
      # from the request so that we only have recipe_data.
      request['request_options'].pop('recipe_name')
      # recipe_data should be a UTF-8 encoded string.
      request['request_options']['recipe_data'] = recipe_data.decode('utf-8')
  else:
    log.error('Unable to load recipe from file %s', recipe_name)

  # Send the request to the API server.
  try:
    log.debug('Sending request: %s', request)
    api_response = api_instance.create_request(request)
    log.debug('Received response: %s', api_response)
  except exceptions.ApiException as exception:
    log.error(
        'Received status code %s when calling create_request. %s',
        exception.status, exception.body)
  except (TypeError, exceptions.ApiTypeError) as exception:
    log.error('The request object is invalid. %s', exception)
