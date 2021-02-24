# -*- coding: utf-8 -*-
# Copyright 2021 Google Inc.
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
"""Library to contain recipe validation logic."""

import copy
import logging
from turbinia import config
from turbinia import TurbiniaException
from yaml import Loader, load, dump
from turbinia.lib.file_helpers import file_to_str, file_to_list

log = logging.getLogger('turbinia')

#Attributes allowed on the 'globals' task recipe
DEFAULT_GLOBALS_RECIPE = {
    'debug_tasks': False,
    'jobs_allowlist': [],
    'jobs_denylist': [],
    'yara_rules': '',
    'filter_patterns': [],
    'yara_rules_file': None,
    'filter_patterns_file': None
}

#Default 'task_recipes' dict
DEFAULT_RECIPE = {'globals': DEFAULT_GLOBALS_RECIPE}


def load_recipe_from_file(recipe_file):
  """ Load recipe from file. """
  if not recipe_file:
    task_recipe = DEFAULT_RECIPE
  else:
    try:
      with open(recipe_file, 'r') as r_file:
        recipe_file_contents = r_file.read()
        recipe_dict = load(recipe_file_contents, Loader=Loader)
    except yaml.parser.ParserError as exception:
      message = (
          'Invalid YAML on recipe file {0:s}: {1!s}.'.format(
              recipe_file, exception))
      return False
      raise TurbiniaException(message)
    except IOError as exception:
      raise TurbiniaException(
          'Failed to read recipe file {0:s}: {1!s}'.format(
              recipe_file, exception))
      validate_recipe_dict(recipe_dict)
      return False
    return recipe_dict


def validate_globals_recipe(proposed_globals_recipe):
  """Ensures globals recipe is valid for further processing."""

  for item in DEFAULT_GLOBALS_RECIPE:
    if item not in proposed_globals_recipe:
      proposed_globals_recipe[item] = DEFAULT_GLOBALS_RECIPE[item]

  filter_patterns_file = proposed_globals_recipe.get(
      'filter_patterns_file', None)
  yara_rules_file = proposed_globals_recipe.get('yara_rules_file', None)
  if filter_patterns_file:
    proposed_globals_recipe['filter_patterns'] = file_to_list(
        filter_patterns_file)
  if yara_rules_file:
    proposed_globals_recipe['yara_rules'] = file_to_str(yara_rules_file)
  diff = set(DEFAULT_GLOBALS_RECIPE) - set(proposed_globals_recipe)
  if diff:
    log.error('Unknown key {0:s} found on globals recipe item'.format(diff))
    return False

  if any(i in proposed_globals_recipe['jobs_denylist']
         for i in proposed_globals_recipe['jobs_allowlist']):
    raise TurbiniaException(
        'No jobs can be simultaneously in the allow and deny lists')
    return False
  return True


def validate_recipe_dict(recipe_dict):
  """Validate the 'task_recipes' dict supplied by the request recipe."""
  tasks_with_recipe = []
  valid_config = True
  #If not globals task recipe is specified create one.
  if 'globals' not in recipe_dict:
    recipe_dict['globals'] = copy.deepcopy(DEFAULT_RECIPE)
    log.warning(
        'No globals recipe specified, all recipes should include a globals entry, the default values will be used'
    )

  for recipe_item, recipe_item_contents in recipe_dict.items():
    if recipe_item in tasks_with_recipe:
      raise TurbiniaException(
          'Two recipe items with the same name {0:s} have been found.'
          'If you wish to specify several task runs of the same tool,'
          'please include them in separate recipes.'.format(recipe_item))
      valid_config = False
    if 'task' not in recipe_item_contents:
      if recipe_item != 'globals':
        raise TurbiniaException(
            'Recipe item {0:s} has no "task" key. All recipe items must have a "task" key indicating the TurbiniaTask'
            ' to which it relates.'.format(recipe_item))
        valid_config = False
      else:
        if not validate_globals_recipe(recipe_item_contents):
          raise TurbiniaException('Invalid globals recipe.')
          valid_config = False

    tasks_with_recipe.append(recipe_item)
  return valid_config
