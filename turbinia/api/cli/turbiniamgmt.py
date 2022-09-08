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
import turbinia_api_client

from turbinia_api_client.api import turbinia_configuration_api
from turbinia.api.cli.core import groups
from turbinia.api.cli.factory import factory
from turbinia.api.cli.helpers import auth_helpers

_LOGGER_FORMAT = '%(asctime)s %(levelname)s %(name)s - %(message)s'
logging.basicConfig(format=_LOGGER_FORMAT)
log = logging.getLogger('turbiniamgmt')
log.setLevel(logging.DEBUG)


class TurbiniaMgmtCli:
  """Turbinia API client tool."""

  def __init__(self, api_client=None, config=None):
    self.API_SERVER_ADDRESS = None
    self.API_SERVER_PORT = None
    self.API_AUTHENTICATION_ENABLED = None
    self.read_api_configuration()
    self._api_client = api_client
    self._config = config

    if not self.config:
      host = 'http://{0:s}:{1:d}'.format(
          self.API_SERVER_ADDRESS, self.API_SERVER_PORT)
      self.config = self.default_config(host)
    if not self.api_client:
      self.api_client = self.default_api_client(self.config)

    if self.API_AUTHENTICATION_ENABLED:
      config.access_token = auth_helpers.get_oauth2_credentials()

    self.evidence_mapping = self.get_evidence_arguments()
    self.request_options = self.get_request_options()

  @property
  def api_client(self):
    """Returns an API client object."""
    return self._api_client

  @api_client.setter
  def api_client(self, api_client):
    self._api_client = api_client

  @property
  def config(self):
    """Returns an API client configuration object."""
    return self._config

  @config.setter
  def config(self, config):
    self._config = config

  def default_api_client(self, config):
    """Default value for API client instance."""
    return turbinia_api_client.ApiClient(configuration=config)

  def default_config(self, host):
    """Default value for API client configuration."""
    return turbinia_api_client.Configuration(host=host)

  def get_evidence_arguments(self, evidence_name=None):
    """Gets arguments for Evidence types."""
    api_instance = turbinia_configuration_api.TurbiniaConfigurationApi(
        self.api_client)
    try:
      if evidence_name:
        api_response = api_instance.get_evidence_attributes_by_name(
            evidence_name)
      else:
        api_response = api_instance.get_evidence_types()
      self.evidence_mapping = api_response
    except turbinia_api_client.ApiException as exception:
      log.exception(
          'Exception when calling read_config: {0!s}'.format(exception))
    return api_response

  def get_request_options(self):
    """Gets BaseRequestOptions attributes."""
    api_instance = turbinia_configuration_api.TurbiniaConfigurationApi(
        self.api_client)
    try:
      api_response = api_instance.get_request_options()
    except turbinia_api_client.ApiException as exception:
      log.exception(
          'Exception when calling read_config: {0!s}'.format(exception))
    return api_response

  def read_api_configuration(self):
    """Reads the configuration file to obtain the API server URI."""
    client_config_path = os.path.realpath(__file__)
    client_config_path = os.path.dirname(os.path.dirname(client_config_path))
    client_config_path = os.path.join(
        client_config_path, '.turbinia_api_config.json')
    with open(client_config_path, encoding='utf-8') as config:
      try:
        config_dict = json.loads(config.read())
        self.API_SERVER_ADDRESS = config_dict.get('API_SERVER_ADDRESS')
        self.API_SERVER_PORT = config_dict.get('API_SERVER_PORT')
        self.API_AUTHENTICATION_ENABLED = config_dict.get(
            'API_AUTHENTICATION_ENABLED')
      except json.JSONDecodeError as exception:
        log.error(exception)


@click.group(context_settings={'help_option_names': ['-h', '--help']})
@click.pass_context
def cli(ctx):
  """Main context for the Click command-line application."""
  ctx.obj = TurbiniaMgmtCli()
  request_commands = factory.CommandFactory.create_dynamic_objects(
      evidence_mapping=ctx.obj.evidence_mapping,
      request_options=ctx.obj.request_options)
  for command in request_commands:
    groups.submit_group.add_command(command)


# Register all command groups.
cli.add_command(groups.submit_group)
cli.add_command(groups.config_group)
cli.add_command(groups.jobs_group)
cli.add_command(groups.result_group)
cli.add_command(groups.status_group)

if __name__ == '__main__':
  cli()
