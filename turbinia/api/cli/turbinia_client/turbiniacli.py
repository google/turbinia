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
import sys
import logging
import json
import turbinia_api_lib
from typing import Union

from turbinia_api_lib.api import turbinia_configuration_api
from turbinia_api_lib.api import turbinia_evidence_api

from turbinia_client.helpers import auth_helper
from turbinia_client.helpers import formatter

log = logging.getLogger(__name__)


class TurbiniaCli:
  """Turbinia API client tool.

  Attributes:
    _api_client (turbinia_api_lib.ApiClient): An instance of the ApiClient
        class.
    _config (turbinia_api_lib.Configuration): An instance of the
        Configuration class.
    _config_dict (dict): Contains all the cli configuration keys and values
        from the config file.
    _evidence_mapping (dict): Internal dictionary used to map Evidence object
        names to Click commands.
    _request_options (dict): Internal dictinoary used to map Request options
        to Click options.
    api_server_address (str): URL for the API server.
    api_server_port (int): Port for the API server.
    api_authentication_enabled (bool): If set to True, the client will attempt
        to authenticate.
    client_secrets_path (str): Full path to the client secrets file used for
        authentication.
    config_instance (str): A name defined in the configuration file that holds
        all the configuration options for a specific Turbinia deployment.
    config_path (str): Full path to the directory containing the cli tool's
        configuration file.
    credentials_path (str): Full path to the credentials cache file used for
        re-authentication.
    id_token (str): An access token to use for authentication.
  """

  def __init__(self, config_instance=None, config_path=None, id_token=None):
    self._api_client: turbinia_api_lib.ApiClient = None
    self._config: turbinia_api_lib.Configuration = None
    self._config_dict: dict[str, str] = {}
    self._evidence_mapping: dict[str, str] = {}
    self._request_options: dict[str, str] = {}
    self.api_server_address: str = None
    self.api_server_port: int = None
    self.api_authentication_enabled: str = None
    self.client_secrets_path: str = None
    self.config_instance: str = config_instance
    self.config_path: str = config_path
    self.credentials_path: str = None
    self.id_token: str = id_token

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

    if self.id_token:
      log.debug('Using user provided id_token')
      # Class attribute config.access_token is not changed to id_token to not
      # break OpenAPIs config automation.
      self.config.access_token = self.id_token
    elif self.api_authentication_enabled:
      log.debug(
          f'Authentication is enabled. Using client_secrets file at: '
          f'{self.client_secrets_path:s} and caching credentials at: '
          f'{self.credentials_path:s}')
      self.config.access_token = auth_helper.get_oauth2_token_id(
          self.credentials_path, self.client_secrets_path)

    log.debug(
        f'Using configuration instance name -> {self.config_instance:s}'
        f' with host {self.api_server_address:s}:{self.api_server_port:d}')

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

  @property
  def config_dict(self):
    """Returns an API client configuration object."""
    return self._config_dict

  @config_dict.setter
  def config_dict(self, config_dict):
    self._config_dict = config_dict

  @property
  def evidence_mapping(self):
    """Returns a dictionary that contains Evidence object data."""
    return self._evidence_mapping

  @evidence_mapping.setter
  def evidence_mapping(self, evidence_mapping):
    self._evidence_mapping = evidence_mapping

  @property
  def request_options(self):
    """Returns a dictionary that contains RequestOptions object data."""
    return self._request_options

  @request_options.setter
  def request_options(self, request_options):
    self._request_options = request_options

  def default_api_client(
      self,
      config: turbinia_api_lib.Configuration) -> turbinia_api_lib.ApiClient:
    """Default value for API client instance."""
    config.retries = 3
    return turbinia_api_lib.ApiClient(configuration=config)

  def default_config(self, host: str) -> turbinia_api_lib.Configuration:
    """Default value for API client configuration."""
    return turbinia_api_lib.Configuration(host=host)

  def get_evidence_arguments(self, evidence_name=None) -> dict[str, str]:
    """Gets arguments for Evidence types."""
    api_instance = turbinia_evidence_api.TurbiniaEvidenceApi(self.api_client)
    if evidence_name:
      api_response = api_instance.get_evidence_attributes_with_http_info(
          evidence_name)
    else:
      api_response = api_instance.get_evidence_types_with_http_info()
    decoded_response = formatter.decode_api_response(api_response)
    self._evidence_mapping = decoded_response
    return decoded_response

  def get_request_options(self) -> dict[str, str]:
    """Gets BaseRequestOptions attributes."""
    api_instance = turbinia_configuration_api.TurbiniaConfigurationApi(
        self.api_client)
    api_response = api_instance.get_request_options_with_http_info()
    return formatter.decode_api_response(api_response)

  def read_api_configuration(self) -> None:
    """Reads the configuration file to obtain the API server URI."""
    if self.config_path == '~':
      client_config_path = os.path.expanduser('~')
      client_config_path = os.path.join(
          client_config_path, '.turbinia_api_config.json')
    else:
      client_config_path = os.path.join(
          self.config_path, '.turbinia_api_config.json')
    try:
      with open(client_config_path, encoding='utf-8') as config:
        config_data = json.loads(config.read())
        config_dict = config_data.get(self.config_instance)
        if not config_dict:
          log.error(f'Error reading configuration key {self.config_instance:s}')
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
        self.config_dict = config_dict
    except (IOError, FileNotFoundError) as exception:
      log.error(f'Unable to read the configuration file {exception!s}')
      sys.exit(-1)
    except json.JSONDecodeError as exception:
      log.error(f'Error decoding configuration file: {exception!s}')
      sys.exit(-1)
    except KeyError as exception:
      log.error(f'Required configuration key not found: {exception!s}')
      sys.exit(-1)

  def normalize_evidence_name(self, evidence_name_low: str) -> Union[str, None]:
    """Converts a lowercase evidence name into the proper class name."""
    evidence_name = None
    evidence_name_low = evidence_name_low.lower()
    if evidence_name_low:
      for name in self.evidence_mapping.keys():
        if evidence_name_low == name.lower():
          evidence_name = name
          break

    if not evidence_name:
      log.error(f'Unable to map {evidence_name_low} to a valid Evidence name.')
      sys.exit(-1)

    return evidence_name
