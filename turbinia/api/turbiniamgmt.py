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
import sys
import logging
import click
import turbinia_api_client

from google_auth_oauthlib import flow
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request
from turbinia_api_client.api import turbinia_requests_api
from turbinia_api_client.api import turbinia_tasks_api
from turbinia_api_client.api import turbinia_configuration_api
from turbinia_api_client.api import turbinia_jobs_api
from turbinia_api_client.api import turbinia_request_results_api
from turbinia import config as turbinia_config

log = logging.getLogger('turbinia:turbiniamgmt')
stdout_handler = logging.StreamHandler(stream=sys.stdout)
stdout_handler.setLevel(logging.DEBUG)
log.addHandler(stdout_handler)


def load_config():
  """Load the API client configuration."""
  turbinia_config.LoadConfig()
  config = turbinia_api_client.Configuration(
      host='{}:{}'.format(
          turbinia_config.API_SERVER_ADDRESS, turbinia_config.API_SERVER_PORT))
  return config


def get_oauth2_credentials():
  """Authenticate the user using Google OAuth services."""
  scopes = [
      'openid', 'https://www.googleapis.com/auth/userinfo.email',
      'https://www.googleapis.com/auth/userinfo.profile'
  ]
  _CREDENTIALS_FILENAME = 'credentials.json'
  _CLIENT_SECRETS_FILENAME = 'client_secrets.json'

  credentials = None

  # Load credentials file if it exists
  if os.path.exists(_CREDENTIALS_FILENAME):
    click.echo('Attempting to use existing OAuth2 token...')
    try:
      credentials = Credentials.from_authorized_user_file(
          _CREDENTIALS_FILENAME, scopes)
    except ValueError as exception:
      click.echo('Error loading credentials: {0:s}'.format(exception))
    # Refresh credentials using existing refresh_token or obtain a new token
    if credentials:
      click.echo(
          'Could not find a valid OAuth2 id_token, checking refresh token.')
      if credentials.refresh_token:
        click.echo('Found a refresh token. Requesting new id_token...')
        credentials.refresh(Request())
  else:
    # No refresh token, obtain new credentials via OAuth2 flow
    click.echo('Could not find existing credentials. Requesting new tokens.')
    appflow = flow.InstalledAppFlow.from_client_secrets_file(
        _CLIENT_SECRETS_FILENAME, scopes)
    appflow.run_console()
    credentials = appflow.credentials
    # Save credentials
    with open(_CREDENTIALS_FILENAME, 'w', encoding='utf-8') as token:
      token.write(credentials.to_json())

  click.echo('OAuth2 token: {}'.format(credentials.id_token))
  return credentials.id_token


@click.group("request")
def request_group():
  """Manage Turbinia requests."""


@click.group("task")
def task_group():
  """Get Turbinia task information."""


@click.group("config")
def config_group():
  """Get turbinia configuration."""


@click.group("result")
def result_group():
  """Get turbinia task or request results."""


@click.group("jobs")
def jobs_group():
  """Get a list of enabled Turbinia jobs."""


@config_group.command("get_config")
@click.pass_context
def get_config(ctx):
  """Get Turbinia server configuration."""
  api_client = ctx.obj.api_client
  api_instance = turbinia_configuration_api.TurbiniaConfigurationApi(api_client)
  try:
    api_response = api_instance.read_config()
    click.echo(api_response)
  except turbinia_api_client.ApiException as e:
    click.echo("Exception when calling read_config: %s\n" % e)


@result_group.command("get_request_result")
@click.option(
    "--request_id", '-r', type=str, required=True, help="Request identifier.")
@click.pass_context
def get_request_result(ctx, request_id):
  """Get Turbinia server configuration."""
  api_client = ctx.obj.api_client
  api_instance = turbinia_request_results_api.TurbiniaRequestResultsApi(
      api_client)
  try:
    api_response = api_instance.get_request_output(request_id)
    click.echo(api_response)
  except turbinia_api_client.ApiException as e:
    click.echo("Exception when calling read_config: %s\n" % e)


@result_group.command("get_task_result")
@click.option(
    "--task_id", '-t', type=str, required=True, help="Task identifier.")
@click.pass_context
def get_task_result(ctx, task_id):
  """Get Turbinia server configuration."""
  api_client = ctx.obj.api_client
  api_instance = turbinia_request_results_api.TurbiniaRequestResultsApi(
      api_client)
  try:
    api_response = api_instance.get_task_output(
        task_id, _check_return_type=False)
    click.echo(api_response)
  except turbinia_api_client.ApiException as e:
    click.echo("Exception when calling read_config: %s\n" % e)


@jobs_group.command("get_jobs")
@click.pass_context
def get_jobs(ctx):
  """Get Turbinia jobs list."""
  api_client = ctx.obj.api_client
  api_instance = turbinia_jobs_api.TurbiniaJobsApi(api_client)
  try:
    api_response = api_instance.read_jobs()
    click.echo(api_response)
  except turbinia_api_client.ApiException as e:
    click.echo("Exception when calling read_jobs: %s\n" % e)


@request_group.command("get_status")
@click.option(
    "--request_id", '-r', type=str, required=True, help="Request identifier.")
@click.pass_context
def get_request(ctx, request_id):
  """Get Turbinia request status."""
  api_client = ctx.obj.api_client
  api_instance = turbinia_requests_api.TurbiniaRequestsApi(api_client)
  try:
    api_response = api_instance.get_request_status(
        request_id, _check_return_type=False)
    click.echo(api_response)
  except turbinia_api_client.ApiException as e:
    click.echo("Exception when calling get_request_status: %s\n" % e)


@request_group.command("get_summary")
@click.pass_context
def get_requests_summary(ctx):
  """Get a summary of all Trubinia requests."""
  api_client = ctx.obj.api_client
  api_instance = turbinia_requests_api.TurbiniaRequestsApi(api_client)
  try:
    api_response = api_instance.get_requests_summary(_check_return_type=False)
    click.echo(api_response)
  except turbinia_api_client.ApiException as e:
    click.echo("Exception when calling get_requests_summary: %s\n" % e)


@task_group.command("get_status")
@click.option(
    "--task_id", '-t', type=str, required=True, help="Task identifier.")
@click.pass_context
def get_task(ctx, task_id):
  """Get Turbinia task status."""
  api_client = ctx.obj.api_client
  api_instance = turbinia_tasks_api.TurbiniaTasksApi(api_client)
  try:
    api_response = api_instance.get_task_status(
        task_id, _check_return_type=False)
    click.echo(api_response)
  except turbinia_api_client.ApiException as e:
    click.echo("Exception when calling get_task_status: %s\n" % e)


class TurbiniaMgmtCli():
  """Turbinia API client tool."""

  def __init__(self, api_client=None, config=None):
    self.api_client = api_client
    self.config = config

    if not self.config:
      self.config = turbinia_api_client.Configuration(
          host="http://localhost:8000")
    if not self.api_client:
      self.api_client = turbinia_api_client.ApiClient(configuration=config)

    if turbinia_config.API_AUTHENTICATION_ENABLED:
      config.access_token = get_oauth2_credentials()


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.pass_context
def cli(ctx):
  """Turbinia API client tool."""
  config = load_config()
  ctx.obj = TurbiniaMgmtCli(config=config)


cli.add_command(config_group)
cli.add_command(jobs_group)
cli.add_command(request_group)
cli.add_command(result_group)
cli.add_command(task_group)

if __name__ == "__main__":
  cli()
