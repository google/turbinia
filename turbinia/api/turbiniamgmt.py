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
import json
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

log = logging.getLogger('turbinia:turbiniamgmt')
stdout_handler = logging.StreamHandler(stream=sys.stdout)
stdout_handler.setLevel(logging.DEBUG)
log.addHandler(stdout_handler)


def get_oauth2_credentials():
  """Authenticates the user using Google OAuth services."""
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
  except turbinia_api_client.ApiException as exception:
    click.echo("Exception when calling read_config: {0!s}".format(exception))


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
    filename = api_response.name.split('/')[-1]
    click.echo("Saving zip file: {}".format(filename))
    with open(filename, 'wb') as file:
      file.write(api_response.read())
  except turbinia_api_client.ApiException as exception:
    click.echo(
        "Exception when calling get_request_result: {0!s}".format(exception))
  except OSError as exception:
    click.echo("Unable to save file: {0!s}".format(exception))


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
    filename = api_response.name.split('/')[-1]
    click.echo("Saving zip file: {}".format(filename))
    with open(filename, 'wb') as file:
      file.write(api_response.read())
  except turbinia_api_client.ApiException as exception:
    click.echo(
        "Exception when calling get_task_result: {0!s}".format(exception))
  except OSError as exception:
    click.echo("Unable to save file: {0!s}".format(exception))


@jobs_group.command("get_jobs")
@click.pass_context
def get_jobs(ctx):
  """Get Turbinia jobs list."""
  api_client = ctx.obj.api_client
  api_instance = turbinia_jobs_api.TurbiniaJobsApi(api_client)
  try:
    api_response = api_instance.read_jobs()
    click.echo(api_response)
  except turbinia_api_client.ApiException as exception:
    click.echo("Exception when calling get_jobs: %s\n" % exception)


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
  except turbinia_api_client.ApiException as exception:
    click.echo("Exception when calling get_status: {0!s}".format(exception))


@request_group.command("get_summary")
@click.pass_context
def get_requests_summary(ctx):
  """Get a summary of all Trubinia requests."""
  api_client = ctx.obj.api_client
  api_instance = turbinia_requests_api.TurbiniaRequestsApi(api_client)
  try:
    api_response = api_instance.get_requests_summary(_check_return_type=False)
    click.echo(api_response)
  except turbinia_api_client.ApiException as exception:
    click.echo("Exception when calling get_summary: {0!s}".format(exception))


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
  except turbinia_api_client.ApiException as exception:
    click.echo("Exception when calling get_status: {0!s}".format(exception))


class TurbiniaMgmtCli():
  """Turbinia API client tool."""

  def __init__(self, api_client=None, config=None):
    self.API_SERVER_ADDRESS = None
    self.API_SERVER_PORT = None
    self.API_AUTHENTICATION_ENABLED = None
    self.get_api_uri()
    self.api_client = api_client
    self.config = config

    if not self.config:
      host = 'http://{0:s}:{1:d}'.format(
          self.API_SERVER_ADDRESS, self.API_SERVER_PORT)
      self.config = turbinia_api_client.Configuration(host=host)
    if not self.api_client:
      self.api_client = turbinia_api_client.ApiClient(configuration=self.config)

    if self.API_AUTHENTICATION_ENABLED:
      config.access_token = get_oauth2_credentials()

  def get_api_uri(self):
    """Reads the configuration file to obtain the API server URI."""
    with open(".turbinia_api_config.json", encoding='utf-8') as config:
      try:
        config_dict = json.loads(config.read())
        self.API_SERVER_ADDRESS = config_dict.get('API_SERVER_ADDRESS')
        self.API_SERVER_PORT = config_dict.get('API_SERVER_PORT')
        self.API_AUTHENTICATION_ENABLED = config_dict.get(
            'API_AUTHENTICATION_ENABLED')
      except json.JSONDecodeError as exception:
        log.error(exception)
        click.echo(
            "Error reading .turbinia_api_config.json: {0!s}".format(exception))


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.pass_context
def cli(ctx):
  """Turbinia API client tool."""
  ctx.obj = TurbiniaMgmtCli()


cli.add_command(config_group)
cli.add_command(jobs_group)
cli.add_command(request_group)
cli.add_command(result_group)
cli.add_command(task_group)

if __name__ == "__main__":
  cli()
