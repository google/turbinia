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

from abc import ABC, abstractmethod

import logging
import click

from turbinia.api.cli.helpers import click_helpers
from turbinia.api.cli.core.commands import create_request

_LOGGER_FORMAT = '%(asctime)s %(levelname)s %(name)s %(message)s'
logging.basicConfig(format=_LOGGER_FORMAT)
log = logging.getLogger()


class FactoryInterface(ABC):
  """Factory Interface."""

  @classmethod
  def get_evidence_names(cls, evidence_mapping):
    """Retrieves a list of evidence type names."""
    return [evidence_name for evidence_name in evidence_mapping.keys()]

  @classmethod
  def get_request_options(cls, options_dictionary):
    """Retrieves a list of request options"""
    return [request_option for request_option in options_dictionary.keys()]

  @classmethod
  def get_evidence_attributes(cls, evidence_mapping):
    """Retrieves a list of evidence attribute metadata."""
    map_types = dict(str=str, int=int)
    options_meta = []
    for evidence_name, options in evidence_mapping.items():
      for option in options.items():
        (option_name, option_parameters) = option
        param_decls = (['--' + option_name], option_name)
        param_type = map_types.get(option_parameters.get('type'))
        attrs = dict(
            required=option_parameters.get('required'), type=param_type)
        options_meta.append((evidence_name, param_decls, attrs))
    return options_meta

  @classmethod
  @abstractmethod
  def create_dynamic_objects(cls, name, evidence_params, request_params):
    """Creates multiple objects."""
    raise NotImplementedError

  @classmethod
  @abstractmethod
  def create_object(cls, name, params):
    """Creates an object of a specific type."""
    raise NotImplementedError


class OptionFactory(FactoryInterface):
  """Command line options factory class."""

  @classmethod
  def append_request_option_objects(cls, params, request_options_data):
    """Appends request options to a list of parameters for a click.Command object."""
    for request_option in OptionFactory.get_request_options(
        request_options_data):
      request_parameters = click_helpers.generate_option_parameters(
          request_option)
      params.append(OptionFactory.create_object(params=request_parameters))

  @classmethod
  def create_dynamic_objects(
      cls, name=None, evidence_params=None, request_params=None):
    """Creates a list of click.Option objects."""
    option_objects = []
    if not name:
      log.info('An evidence type was not provided.')
      return []
    options = OptionFactory.get_evidence_attributes(evidence_params)
    for option in options:
      (evidence_name, param_decls, attrs) = option
      if name == evidence_name:
        log.debug('Creating option for {0:s}'.format(name))
        click_option = OptionFactory.create_object(params=(param_decls, attrs))
        option_objects.append(click_option)
    return option_objects

  @classmethod
  def create_object(cls, name=None, params=None):
    """Creates a click.Option object with specified parameters."""
    option = None
    if params:
      (param_decls, attrs) = params
      option = click.Option(*param_decls, **attrs)
    return option


class CommandFactory(FactoryInterface):
  """Commands factory class."""

  @classmethod
  def create_dynamic_objects(
      cls, name=None, evidence_params=None, request_params=None):
    """Creates a list of click.Command objects."""

    command_objects = []
    for evidence_name in CommandFactory.get_evidence_names(evidence_params):
      log.debug('Creating command for {0:s}'.format(evidence_name))
      params = OptionFactory.create_dynamic_objects(
          name=evidence_name, evidence_params=evidence_params,
          request_params=request_params)
      OptionFactory.append_request_option_objects(params, request_params)
      cmd = click.Command(
          name=evidence_name, params=params, callback=create_request)
      command_objects.append(cmd)
    return command_objects

  @classmethod
  def create_object(cls, name=None, params=None):
    return click.Command(name=name, params=params)
