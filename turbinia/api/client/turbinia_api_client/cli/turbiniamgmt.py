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

from urllib3 import exceptions as urllib3_exceptions

from turbinia_api_client.api import turbinia_configuration_api
from turbinia_api_client.cli.core import groups
from turbinia_api_client.cli.factory import factory
from turbinia_api_client.cli.helpers import auth_helper

_LOGGER_FORMAT = '%(asctime)s %(levelname)s %(name)s - %(message)s'
logging.basicConfig(format=_LOGGER_FORMAT)
log = logging.getLogger('turbiniamgmt')
log.setLevel(logging.DEBUG)


class TurbiniaMgmtCli:
  """Turbinia API client tool."""

  def __init__(self, config_instance=None, config_path=None):
    self.api_server_address: str = None
    self.api_server_port: int = None
    self.api_authentication_enabled: str = None
    self.credentials_path: str = None
    self.client_secrets_path: str = None
    self.config_instance: str = config_instance
    self.config_path: str = config_path
    self._api_client: turbinia_api_client.ApiClient = None
    self._config: turbinia_api_client.Configuration = None
    self._config_dict: dict = {}
    self.evidence_mapping: dict = {}
    self.request_options: dict = {}

  def setup(self) -> None:
    """Sets up necessary attributes and preflight requests to the API server.

    The preflight requests get_evidence_arguments and get_request_options
    are used to dynamically build command options.
    """

    # Initialize attributes from config file.
    self.read_api_configuration()

    if not self.config:
      host = f'{self.api_server_address:s}:{self.api_server_port:d}'
      self.config = self.default_config(host)
    if not self.api_client:
      self.api_client = self.default_api_client(self.config)

    if self.api_authentication_enabled:
      log.info(
          'Authentication is enabled. Using client_secrets file at: %s '
          'and caching credentials at: %s', self.client_secrets_path,
          self.credentials_path)
      self.config.access_token = auth_helper.get_oauth2_credentials(
          self.credentials_path, self.client_secrets_path)

    log.info(
        'Using configuration instance name -> %s, with host %s:%s',
        self.config_instance, self.api_server_address, self.api_server_port)
    try:
      self.evidence_mapping = self.get_evidence_arguments()
      self.request_options = self.get_request_options()
    except turbinia_api_client.ApiException as exception:
      log.error(
          'Error while attempting to contact the API server during setup: %s',
          exception)
      sys.exit(-1)

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

  def default_api_client(
      self, config: turbinia_api_client.Configuration
  ) -> turbinia_api_client.ApiClient:
    """Default value for API client instance."""
    return turbinia_api_client.ApiClient(configuration=config)

  def default_config(self, host: str) -> turbinia_api_client.Configuration:
    """Default value for API client configuration."""
    return turbinia_api_client.Configuration(host=host)

  def get_evidence_arguments(self, evidence_name=None) -> dict:
    """Gets arguments for Evidence types."""
    api_instance = turbinia_configuration_api.TurbiniaConfigurationApi(
        self.api_client)
    api_response = None
    if evidence_name:
      api_response = api_instance.get_evidence_attributes_by_name(evidence_name)
    else:
      api_response = api_instance.get_evidence_types()

    self.evidence_mapping: dict = api_response
    return api_response

  def get_request_options(self) -> dict:
    """Gets BaseRequestOptions attributes."""
    api_response = None
    api_instance = turbinia_configuration_api.TurbiniaConfigurationApi(
        self.api_client)
    api_response = api_instance.get_request_options()

    return api_response

  def read_api_configuration(self) -> None:
    """Reads the configuration file to obtain the API server URI."""
    if self.config_path == '~':
      client_config_path = os.path.expanduser('~')
      client_config_path = os.path.join(
          client_config_path, '.turbinia_api_config.json')
    else:
      client_config_path = os.path.join(
          self.config_path, '.turbinia_api_config.json')
    with open(client_config_path, encoding='utf-8') as config:
      try:
        config_data = json.loads(config.read())
        config_dict = config_data.get(self.config_instance)
        if not config_dict:
          log.error('Error reading configuration key %s.', self.config_instance)
          sys.exit(-1)
        self.api_server_address = config_dict['API_SERVER_ADDRESS']
        self.api_server_port = config_dict['API_SERVER_PORT']
        self.api_authentication_enabled = config_dict[
            'API_AUTHENTICATION_ENABLED']
        credentials_filename = config_dict['CREDENTIALS_FILENAME']
        client_secrets_filename = config_dict['CLIENT_SECRETS_FILENAME']
        home_path = os.path.expanduser('~')
        self.credentials_path = os.path.join(home_path, credentials_filename)
        self.client_secrets_path = os.path.join(
            home_path, client_secrets_filename)
        self._config_dict = config_dict
      except json.JSONDecodeError as exception:
        log.error('Error decoding configuration file: %s', exception)
        sys.exit(-1)
      except KeyError as exception:
        log.error('Required configuration key not found: %s', exception)
        sys.exit(-1)


@click.group(context_settings={
    'help_option_names': ['-h', '--help'],
})
@click.option(
    '--config_instance', '-c', help='A Turbinia instance configuration name.',
    show_default=True, show_envvar=True, type=str,
    default=lambda: os.environ.get('TURBINIA_CONFIG_TEMPLATE', 'default'))
@click.option(
    '--config_path', '-p', help='Path to the .turbinia_api_config.json file..',
    show_default=True, show_envvar=True, type=str,
    default=lambda: os.environ.get('TURBINIA_CLI_CONFIG_PATH', '~'))
@click.pass_context
def cli(ctx: click.Context, config_instance: str, config_path: str) -> None:
  """Turbinia API command-line tool (turbiniamgmt).
  \b                         ***    ***                                       
  \b                          *          *                                      
  \b                     ***             ******                                 
  \b                    *                      *                                
  \b                    **      *   *  **     ,*                                
  \b                      *******  * ********                                  
  \b                             *  * *                                         
  \b                             *  * *                                         
  \b                             %%%%%%                                         
  \b                             %%%%%%                                         
  \b                    %%%%%%%%%%%%%%%       %%%%%%                            
  \b              %%%%%%%%%%%%%%%%%%%%%      %%%%%%%                            
  \b %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%  ** *******       
  \b %%                                                   %%  ***************   
  \b %%                                (%%%%%%%%%%%%%%%%%%%  *****  **          
  \b   %%%%%        %%%%%%%%%%%%%%%                                             
                                              
  \b   %%%%%%%%%%                     %%          **             ***              
  \b      %%%                         %%  %%             %%%           %%%%,      
  \b      %%%      %%%   %%%   %%%%%  %%%   %%%   %%  %%%   %%%  %%%       (%%    
  \b      %%%      %%%   %%%  %%%     %%     %%/  %%  %%%   %%%  %%%  %%%%%%%%    
  \b      %%%      %%%   %%%  %%%     %%%   %%%   %%  %%%   %%%  %%% %%%   %%%    
  \b      %%%        %%%%%    %%%       %%%%%     %%  %%%    %%  %%%   %%%%%      

  This command-line tool interacts with Turbinia's API server.

  You can specify the API server location in ~/.turbinia_api_config.json
  """
  ctx.obj = TurbiniaMgmtCli(
      config_instance=config_instance, config_path=config_path)

  # Set up the tool based on the configuration file parameters.
  ctx.obj.setup()

  # Build all the commands based on responses from the API server.
  request_commands = factory.CommandFactory.create_dynamic_objects(
      evidence_mapping=ctx.obj.evidence_mapping,
      request_options=ctx.obj.request_options)
  for command in request_commands:
    groups.submit_group.add_command(command)


def main():
  """Initialize the cli application."""

  # Register all command groups.
  cli.add_command(groups.submit_group)
  cli.add_command(groups.config_group)
  cli.add_command(groups.jobs_group)
  cli.add_command(groups.result_group)
  cli.add_command(groups.status_group)

  try:
    cli.main()
  except (ConnectionRefusedError, urllib3_exceptions.MaxRetryError,
          urllib3_exceptions.NewConnectionError) as exception:
    log.error('Error connecting to the Turbinia API server: %s', exception)
    sys.exit(-1)


main()