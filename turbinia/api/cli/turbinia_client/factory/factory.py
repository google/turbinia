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
from typing import TypeVar, Type, Tuple, Any, List

import logging
import click

from turbinia_client.helpers import click_helper

T = TypeVar('T', bound='FactoryInterface')

log = logging.getLogger(__name__)


class FactoryInterface(ABC):
  """Factory Interface."""

  @classmethod
  def get_evidence_attributes(
      cls: Type[T], evidence_mapping: dict) -> List[Tuple[str, Any, dict]]:
    """Retrieves a list of evidence attribute metadata.

    Args:
      evidence_mapping (dict): A dictionary of Evidence types
          and attributes retrieved from the Turbinia API server.

    Returns:
      list: A list of 3-tuples comprising the necessary parameters to create
          new click.Option objects.
    """
    map_types = dict(str=str, int=int)
    options_meta = []
    for evidence_name, options in evidence_mapping.items():
      for option_name, option_parameters in options.items():
        param_decls = (['--' + option_name], option_name)
        param_type = map_types.get(option_parameters.get('type'))
        attrs = dict(
            required=option_parameters.get('required'), type=param_type)
        options_meta.append((evidence_name, param_decls, attrs))
    return options_meta

  @classmethod
  @abstractmethod
  def create_dynamic_objects(
      cls: Type[T], name: str, evidence_mapping: dict,
      request_options: dict) -> None:
    """Creates one or more click.Command or click.Options objects.
    
    Args:
      name (str): Object name.
      evidence_mapping (dict): A dictionary of Evidence types
          and attributes retrieved from the Turbinia API server.
      request_options (dict): A dictionary of BaseRequestOptions
          attributes and types retrieved from the Turbinia APi server.
    """
    raise NotImplementedError

  @classmethod
  @abstractmethod
  def create_object(
      cls: Type[T], name: str, params: Tuple[Any, dict], callback: Any):
    """Creates a click.Command or click.Options object.

    Args:
      name (str): Object name.
      params (tuple): A tuple comprised of arguments needed to create
          click.Option or click.Command objects.
      callback: A callback function.
    """
    raise NotImplementedError


class OptionFactory(FactoryInterface):
  """Command line options factory class."""

  @classmethod
  def append_request_option_objects(
      cls: Type[T], params: List[click.Option],
      request_options: dict = None) -> None:
    """Appends options to a list of parameters for a click.Command object."""
    for request_option in list(request_options.keys()):
      request_parameters = click_helper.generate_option_parameters(
          request_option)
      params.append(OptionFactory.create_object(params=request_parameters))

  @classmethod
  def create_dynamic_objects(
      cls, name: str = None, evidence_mapping: dict = None,
      request_options: dict = None) -> List[click.Option]:
    """Creates a list of click.Option objects."""
    option_objects = []
    if not name:
      log.info('An evidence type was not provided.')
      return []
    options = OptionFactory.get_evidence_attributes(evidence_mapping)
    for evidence_name, param_decls, attrs in options:
      if name == evidence_name:
        log.debug(f'Creating option for {name:s}')
        click_option = OptionFactory.create_object(params=(param_decls, attrs))
        option_objects.append(click_option)
    return option_objects

  @classmethod
  def create_object(
      cls: Type[T], name: str = None, params: Tuple[Any, dict] = None,
      callback=None) -> click.Option:
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
      cls, name: str = None, evidence_mapping: dict = None,
      request_options: dict = None) -> List[click.Command]:
    """Creates a list of click.Command objects."""

    command_objects = []
    for evidence_name in list(evidence_mapping.keys()):
      log.debug(f'Creating command for {evidence_name:s}')
      # Use lowercase evidence names.
      evidence_name_lower = evidence_name.lower()
      params = OptionFactory.create_dynamic_objects(
          name=evidence_name, evidence_mapping=evidence_mapping,
          request_options=request_options)
      OptionFactory.append_request_option_objects(params, request_options)
      cmd = CommandFactory.create_object(
          name=evidence_name_lower, params=params,
          callback=click_helper.create_request)
      command_objects.append(cmd)
    return command_objects

  @classmethod
  def create_object(
      cls: Type[T], name: str = None, params: Tuple[Any, dict] = None,
      callback=None) -> click.Command:
    """Creates a click.Command object with specified parameters."""
    return click.Command(name=name, params=params, callback=callback)
