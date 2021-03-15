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
import yaml
from turbinia import config
from turbinia import TurbiniaException
from yaml import Loader
from yaml import load
from yaml import dump
from turbinia.lib.file_helpers import file_to_str
from turbinia.lib.file_helpers import file_to_list
from turbinia.client import TASK_MAP

log = logging.getLogger('turbinia')

#Attributes allowed on the 'globals' task recipe
DEFAULT_GLOBALS_RECIPE = {
    'debug_tasks': False,
    'jobs_allowlist': [],
    'jobs_denylist': [],
}

#Default 'task_recipes' dict
DEFAULT_RECIPE = {'globals': DEFAULT_GLOBALS_RECIPE}


def load_recipe_from_file(recipe_file):
  """Load recipe from file.
  Args:
    recipe_file(str): Name of the recipe file to be read.

  Returns:
    dict: Validated and corrected recipe dictionary. Empty dict if recipe is invalid.
  """
  if not recipe_file:
    return copy.deepcopy(DEFAULT_RECIPE)
  else:
    try:
      with open(recipe_file, 'r') as r_file:
        recipe_file_contents = r_file.read()
        recipe_dict = load(recipe_file_contents, Loader=Loader)
    except yaml.parser.ParserError as exception:
      message = (
          'Invalid YAML on recipe file {0:s}: {1!s}.'.format(
              recipe_file, exception))
      log.error(message)
    except IOError as exception:
      log.error(
          'Failed to read recipe file {0:s}: {1!s}'.format(
              recipe_file, exception))
    if validate_recipe(recipe_dict):
      return recipe_dict
    else:
      return {}


def validate_globals_recipe(proposed_globals_recipe):
  """Validate the 'globals' special task recipe.
  Args:
    proposed_globals_recipe(dict): globals task recipe in need of validation.

  Returns:
    Bool indicating whether the recipe has a valid format.
  """
  reference_globals_recipe = copy.deepcopy(DEFAULT_GLOBALS_RECIPE)
  reference_globals_recipe.update(proposed_globals_recipe)

  filter_patterns_file = proposed_globals_recipe.get(
      'filter_patterns_file', None)
  yara_rules_file = proposed_globals_recipe.get('yara_rules_file', None)
  if filter_patterns_file:
    proposed_globals_recipe['filter_patterns'] = file_to_list(
        filter_patterns_file)
  if yara_rules_file:
    proposed_globals_recipe['yara_rules'] = file_to_str(yara_rules_file)
  diff =  set(proposed_globals_recipe) - set(DEFAULT_GLOBALS_RECIPE)
  if diff:
    log.error('Unknown key {0:s} found on globals recipe item'.format(diff))
    return False

  if any(i in proposed_globals_recipe['jobs_denylist']
         for i in proposed_globals_recipe['jobs_allowlist']):
    log.error('No jobs can be simultaneously in the allow and deny lists')
    return False
  return True


def validate_task_recipe(proposed_recipe, task_config):
  """Ensure only allowed parameters are present a given task recipe.
  Args:
    proposed_recipe(dict): Task recipe in need of validation.
    task_config(dict): Default recipe for task, defining the allowed fields. 

  Returns:
    Bool indicating whether the recipe has a valid format.
  """
  allowed_values = task_config.keys()
  for v in proposed_recipe:
    if v not in allowed_values:
      return False 
  return True


def validate_recipe(recipe_dict):
  """Validate the 'task_recipes' dict supplied by the request recipe.
  Args:
    recipe_dict(dict): Turbinia recipe in need of validation submitted along with the evidence.

  Returns:
    Bool indicating whether the recipe has a valid format.
  """
  tasks_with_recipe = []
  #If not globals task recipe is specified create one.
  if 'globals' not in recipe_dict:
    recipe_dict['globals'] = copy.deepcopy(DEFAULT_RECIPE)
    log.warning(
        'No globals recipe specified, all recipes should include a globals entry, the default values will be used'
    )
  else:
    if not validate_globals_recipe(recipe_item_contents):
      log.error('Invalid globals recipe.')
      return False

  for recipe_item, recipe_item_contents in recipe_dict.items():
    if recipe_item in tasks_with_recipe:
      log.error(
          'Two recipe items with the same name {0:s} have been found. '
          'If you wish to specify several task runs of the same tool, '
          'please include them in separate recipes.'.format(recipe_item))
      return False
    if 'task' not in recipe_item_contents and recipe_item != 'globals':
      log.error(
          'Recipe item {0:s} has no "task" key. All recipe items must have a "task" key indicating the TurbiniaTask'
          ' to which it relates.'.format(recipe_item))
      return False
    proposed_task = recipe_item_contents['task']
    if lower(proposed_task) not in TASK_MAP:
      log.error(
          'Task {0:s} defined for task recipe {0:s} does not exist.'.format(
              proposed_task, recipe_item))
      return False
    tasks_with_recipe.append(recipe_item)
  return True
