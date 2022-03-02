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
import os

from yaml import Loader
from yaml import load
from turbinia import config
from turbinia.lib.file_helpers import file_to_str
from turbinia.lib.file_helpers import file_to_list
from turbinia.task_utils import TaskLoader

log = logging.getLogger('turbinia')

#Attributes allowed on the 'globals' task recipe
DEFAULT_GLOBALS_RECIPE = {
    'debug_tasks': False,
    'jobs_allowlist': [],
    'jobs_denylist': [],
    'yara_rules': '',
    'filter_patterns': [],
    'sketch_id': None,
    'group_id': ''
}

#Default recipes dict
DEFAULT_RECIPE = {'globals': DEFAULT_GLOBALS_RECIPE}


def load_recipe_from_file(recipe_file, validate=True):
  """Load recipe from file.

  Args:
    recipe_file(str): Name of the recipe file to be read.

  Returns:
    dict: Validated and corrected recipe dictionary.
        Empty dict if recipe is invalid.
  """
  if not recipe_file:
    return copy.deepcopy(DEFAULT_RECIPE)
  try:
    log.info('Loading recipe file from {0:s}'.format(recipe_file))
    with open(recipe_file, 'r') as r_file:
      recipe_file_contents = r_file.read()
      recipe_dict = load(recipe_file_contents, Loader=Loader)
      if validate:
        success, _ = validate_recipe(recipe_dict)
        if success:
          return recipe_dict
      else:
        return recipe_dict
  except yaml.parser.ParserError as exception:
    message = (
        'Invalid YAML on recipe file {0:s}: {1!s}.'.format(
            recipe_file, exception))
    log.error(message)
  except IOError as exception:
    log.error(
        'Failed to read recipe file {0:s}: {1!s}'.format(
            recipe_file, exception))
  return {}


def validate_globals_recipe(proposed_globals_recipe):
  """Validate the 'globals' special task recipe.

  Args:
    proposed_globals_recipe(dict): globals task recipe in need of validation.

  Returns:
    Tuple(
      bool: Whether the recipe has a valid format.
      str: Error message if validation failed.
    )
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
  diff = set(proposed_globals_recipe) - set(DEFAULT_GLOBALS_RECIPE)
  if diff:
    message = (
        'Invalid recipe: Unknown keys [{0:s}] found in globals recipe'.format(
            str(diff)))
    log.error(message)
    return (False, message)

  if (proposed_globals_recipe.get('jobs_allowlist') and
      proposed_globals_recipe.get('jobs_denylist')):
    message = 'Invalid recipe: Jobs cannot be in both the allow and deny lists'
    log.error(message)
    return (False, message)
  return (True, '')


def validate_recipe(recipe_dict):
  """Validate the 'recipe' dict supplied by the request recipe.

  Args:
    recipe_dict(dict): Turbinia recipe in need of validation
    submitted along with the evidence.

  Returns:
    Tuple(
      bool: Whether the recipe has a valid format.
      str: Error message if validation failed.
    )
  """
  tasks_with_recipe = []
  #If not globals task recipe is specified create one.
  if 'globals' not in recipe_dict:
    recipe_dict['globals'] = copy.deepcopy(DEFAULT_RECIPE)
    log.warning(
        'No globals recipe specified, all recipes should include '
        'a globals entry, the default values will be used')
  else:
    success, message = validate_globals_recipe(recipe_dict['globals'])
    if not success:
      log.error(message)
      return (False, message)

  for recipe_item, recipe_item_contents in recipe_dict.items():
    if recipe_item in tasks_with_recipe:
      message = (
          'Two recipe items with the same name \"{0:s}\" have been found. '
          'If you wish to specify several task runs of the same tool, '
          'please include them in separate recipes.'.format(recipe_item))
      log.error(message)
      return (False, message)
    if recipe_item != 'globals':
      if 'task' not in recipe_item_contents:
        message = (
            'Recipe item \"{0:s}\" has no "task" key. All recipe items '
            'must have a "task" key indicating the TurbiniaTask '
            'to which it relates.'.format(recipe_item))
        log.error(message)
        return (False, message)
      proposed_task = recipe_item_contents['task']

      task_loader = TaskLoader()
      if not task_loader.check_task_name(proposed_task):
        message = (
            'Task {0:s} defined for task recipe {1:s} does not '
            'exist.'.format(proposed_task, recipe_item))
        log.error(message)
        return (False, message)
      tasks_with_recipe.append(recipe_item)

  return (True, '')


def get_recipe_path_from_name(recipe_name):
  """Returns a recipe's path from a recipe name.

  Args:
    recipe_name (str): A recipe name.

  Returns:
    str: a recipe's file system path.
  """
  recipe_path = ''
  if not recipe_name.endswith('.yaml'):
    recipe_name = recipe_name + '.yaml'

  if hasattr(config, 'RECIPE_FILE_DIR') and config.RECIPE_FILE_DIR:
    recipe_path = os.path.join(config.RECIPE_FILE_DIR, recipe_name)
  else:
    recipe_path = os.path.realpath(__file__)
    recipe_path = os.path.dirname(recipe_path)
    recipe_path = os.path.join(recipe_path, 'config', 'recipes')
    recipe_path = os.path.join(recipe_path, recipe_name)

  return recipe_path
