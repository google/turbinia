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

import click
import turbinia_api_client

from turbinia_api_client.api import turbinia_requests_api
from turbinia_api_client.api import turbinia_tasks_api
from turbinia_api_client.api import turbinia_configuration_api
from turbinia_api_client.api import turbinia_jobs_api
from turbinia_api_client.api import turbinia_request_results_api

from turbinia.api.cli.core import groups


@groups.config_group.command('list')
@click.pass_context
def get_config(ctx):
  """Get Turbinia server configuration."""
  api_client = ctx.obj.api_client
  api_instance = turbinia_configuration_api.TurbiniaConfigurationApi(api_client)
  try:
    api_response = api_instance.read_config()
    click.echo(api_response)
  except turbinia_api_client.ApiException as exception:
    click.echo('Exception when calling read_config: {0!s}'.format(exception))


@groups.result_group.command('request')
@click.pass_context
@click.argument('request_id')
def get_request_result(ctx, request_id):
  """Get Turbinia server configuration."""
  api_client = ctx.obj.api_client
  api_instance = turbinia_request_results_api.TurbiniaRequestResultsApi(
      api_client)
  try:
    api_response = api_instance.get_request_output(request_id)
    filename = api_response.name.split('/')[-1]
    click.echo("Saving zip file: {}".format(filename))
    with open(filename, 'wb') as file:
      file.write(api_response.read())
  except turbinia_api_client.ApiException as exception:
    click.echo(
        'Exception when calling get_request_result: {0!s}'.format(exception))
  except OSError as exception:
    click.echo('Unable to save file: {0!s}'.format(exception))


@groups.result_group.command('task')
@click.pass_context
@click.argument('task_id')
def get_task_result(ctx, task_id):
  """Get Turbinia server configuration."""
  api_client = ctx.obj.api_client
  api_instance = turbinia_request_results_api.TurbiniaRequestResultsApi(
      api_client)
  try:
    api_response = api_instance.get_task_output(
        task_id, _check_return_type=False)
    filename = api_response.name.split('/')[-1]
    click.echo('Saving zip file: {}'.format(filename))
    with open(filename, 'wb') as file:
      file.write(api_response.read())
  except turbinia_api_client.ApiException as exception:
    click.echo('Error when calling get_task_result: {0!s}'.format(exception))
  except OSError as exception:
    click.echo('Unable to save file: {0!s}'.format(exception))


@groups.jobs_group.command('list')
@click.pass_context
def get_jobs(ctx):
  """Get Turbinia jobs list."""
  api_client = ctx.obj.api_client
  api_instance = turbinia_jobs_api.TurbiniaJobsApi(api_client)
  try:
    api_response = api_instance.read_jobs()
    click.echo(api_response)
  except turbinia_api_client.ApiException as exception:
    click.echo('Error when calling get_jobs: {0!s}'.format(exception))


@groups.status_group.command('request')
@click.pass_context
@click.argument('request_id')
def get_request(ctx, request_id):
  """Get Turbinia request status."""
  api_client = ctx.obj.api_client
  api_instance = turbinia_requests_api.TurbiniaRequestsApi(api_client)
  try:
    api_response = api_instance.get_request_status(
        request_id, _check_return_type=False)
    click.echo(api_response)
  except turbinia_api_client.ApiException as exception:
    click.echo('Error when calling get_status: {0!s}'.format(exception))


@groups.status_group.command('summary')
@click.pass_context
def get_requests_summary(ctx):
  """Get a summary of all Trubinia requests."""
  api_client = ctx.obj.api_client
  api_instance = turbinia_requests_api.TurbiniaRequestsApi(api_client)
  try:
    api_response = api_instance.get_requests_summary(_check_return_type=False)
    click.echo(api_response)
  except turbinia_api_client.ApiException as exception:
    click.echo('Error when calling get_summary: {0!s}'.format(exception))


@groups.status_group.command('task')
@click.pass_context
@click.argument('task_id')
def get_task(ctx, task_id):
  """Get Turbinia task status."""
  api_client = ctx.obj.api_client
  api_instance = turbinia_tasks_api.TurbiniaTasksApi(api_client)
  try:
    api_response = api_instance.get_task_status(
        task_id, _check_return_type=False)
    click.echo(api_response)
  except turbinia_api_client.ApiException as exception:
    click.echo('Error when calling get_status: {0!s}'.format(exception))


@click.pass_context
def create_request(ctx, *args, **kwargs):
  """Create and submit a new Turbinia request."""
  api_client = ctx.obj.api_client
  api_instance = turbinia_requests_api.TurbiniaRequestsApi(api_client)
  evidence_name = ctx.command.name
  print(args, kwargs)
  #request = {'evidence': {}, 'request_options': {}}
  request = {
      "description": "Turbinia request object",
      "evidence": {
          "_name": "Rawdisk evidence",
          "source_path": "/workspaces/turbinia/test_data/artifact_disk.dd",
          "type": "RawDisk"
      },
      "request_options": {
          "sketch_id":
              1234,
          "recipe_name":
              "/workspaces/turbinia/turbinia/config/recipes/triage-linux.yaml"
      },
      "reason": "test",
      "requester": "tester"
  }
  try:
    api_response = api_instance.create_request(request)
    click.echo(api_response)
  except turbinia_api_client.ApiException as exception:
    click.echo('Error when calling create_request: {0!s}'.format(exception))
  except TypeError as exception:
    click.echo('The request object is invalid. {0!s}'.format(exception))
