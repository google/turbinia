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
"""Tests for recipe helpers."""

import io
import os
import unittest
from unittest import mock

from turbinia.lib import recipe_helpers


class RecipeHelpersTest(unittest.TestCase):
  """Tests for recipe_helpers functions."""

  def setUp(self):
    self.test_globals_recipe = {
        'debug_tasks': False,
        'jobs_allowlist': [],
        'jobs_denylist': [],
        'yara_rules': '',
        'filter_patterns': [],
        'sketch_id': None,
        'group_id': ''
    }
    self.test_recipe_dict = {
        'globals': self.test_globals_recipe,
        'plaso_base': {
            'task': 'PlasoTask'
        }
    }

  @mock.patch(
      'builtins.open',
      return_value=io.StringIO('globals:\n  jobs_allowlist:\n    - PlasoJob'))
  def testLoadRecipeFromFile(self, _):
    """Tests that a recipe is loaded correctly."""
    expected = {'globals': {'jobs_allowlist': ['PlasoJob']}}
    result = recipe_helpers.load_recipe_from_file('test.yaml')

    self.assertEqual(result, expected)

  @mock.patch('builtins.open', side_effect=IOError)
  @mock.patch('turbinia.lib.recipe_helpers.log.error')
  def testLoadRecipeFromFileIOError(self, mock_log, _):
    """Tests that an IOError is handled correctly."""
    result = recipe_helpers.load_recipe_from_file('test.yaml')

    mock_log.assert_called_with('Failed to read recipe file test.yaml: ')
    self.assertEqual(result, {})

  @mock.patch('builtins.open', return_value=io.StringIO('{'))
  @mock.patch('turbinia.lib.recipe_helpers.log.error')
  def testLoadRecipeFromFileInvalidYAML(self, mock_log, _):
    """Tests that a YAML parser error is handled correctly."""
    result = recipe_helpers.load_recipe_from_file('test.yaml', validate=False)

    mock_log.assert_called_with(
        'Invalid YAML on recipe file test.yaml: while parsing a flow node\n'
        'expected the node content, but found \'<stream end>\'\n  in "<unicode '
        'string>", line 1, column 2:\n    {\n     ^.')
    self.assertEqual(result, {})

  @mock.patch(
      'builtins.open',
      return_value=io.StringIO('globals:\n  invalid_key:\n    - invalid_value'))
  def testLoadRecipeFromFileInvalidRecipe(self, _):
    """Tests that an invalid recipe is handled correctly."""
    result = recipe_helpers.load_recipe_from_file('test.yaml')
    self.assertEqual(result, {})

  def testValidateGlobalsRecipe(self):
    """Tests validate_globals_recipe for a valid recipe."""
    result = recipe_helpers.validate_globals_recipe(self.test_globals_recipe)
    self.assertEqual(result, (True, ''))

  @mock.patch('turbinia.lib.recipe_helpers.log.error')
  def testValidateGlobalsRecipeInvalidKey(self, mock_log):
    """Tests that an invalid recipe key name is handled correctly."""
    self.test_globals_recipe['invalid_key'] = 'invalid_value'
    expected_error_message = (
        'Invalid recipe: Unknown keys [{\'invalid_key\'}] found in globals '
        'recipe')
    result = recipe_helpers.validate_globals_recipe(self.test_globals_recipe)

    mock_log.assert_called_with(expected_error_message)
    self.assertEqual(result, (False, expected_error_message))

  @mock.patch('turbinia.lib.recipe_helpers.log.error')
  def testValidateGlobalsRecipeAllowDenyListDuplicate(self, mock_log):
    """Tests that an entry in both allow and deny lists is handled correctly."""
    self.test_globals_recipe['jobs_allowlist'].append('job_name')
    self.test_globals_recipe['jobs_denylist'].append('job_name')
    expected_error_message = (
        'Invalid recipe: Jobs cannot be in both the allow and deny lists')
    result = recipe_helpers.validate_globals_recipe(self.test_globals_recipe)

    mock_log.assert_called_with(expected_error_message)
    self.assertEqual(result, (False, expected_error_message))

  def testValidateRecipe(self):
    """Tests that a valid recipe passes validation."""
    result = recipe_helpers.validate_recipe(self.test_recipe_dict)
    self.assertEqual(result, (True, ''))

  @mock.patch('turbinia.lib.recipe_helpers.log.error')
  def testValidateRecipeInvalidGlobals(self, mock_log):
    """Tests that a recipe with invalid globals is handled correctly."""
    recipe_dict = {
        'globals': {
            'invalid_key': 'invalid_value'
        },
        'plaso_base': {
            'task': 'PlasoTask'
        }
    }
    expected_error_message = (
        'Invalid recipe: Unknown keys [{\'invalid_key\'}] found in globals '
        'recipe')
    result = recipe_helpers.validate_recipe(recipe_dict)

    mock_log.assert_called_with(expected_error_message)
    self.assertEqual(result, (False, expected_error_message))

  @mock.patch('turbinia.lib.recipe_helpers.log.error')
  def testValidateRecipeNoTask(self, mock_log):
    """Tests that a recipe with no task key is handled correctly."""
    self.test_recipe_dict['plaso_base'] = {'notask': 'PlasoTask'}
    expected_error_message = (
        'Recipe item "plaso_base" has no "task" key. All recipe items must '
        'have a "task" key indicating the TurbiniaTask to which it relates.')
    result = recipe_helpers.validate_recipe(self.test_recipe_dict)

    mock_log.assert_called_with(expected_error_message)
    self.assertEqual(result, (False, expected_error_message))

  @mock.patch('turbinia.lib.recipe_helpers.log.error')
  def testValidateRecipeInvalidTaskName(self, mock_log):
    """Tests that a recipe with an invalid task name is handled correctly."""
    self.test_recipe_dict['plaso_base'] = {'task': 'NoTask'}
    expected_error_message = (
        'Task NoTask defined for task recipe plaso_base does not exist.')
    result = recipe_helpers.validate_recipe(self.test_recipe_dict)

    mock_log.assert_called_with(expected_error_message)
    self.assertEqual(result, (False, expected_error_message))

  @mock.patch('turbinia.config.RECIPE_FILE_DIR', '/etc/turbinia/', create=True)
  def testGetRecipeFromPathConfigSet(self):
    """Check recipe path is correct when RECIPE_FILE_DIR set."""
    file_path_with_config = recipe_helpers.get_recipe_path_from_name('name')
    self.assertEqual(file_path_with_config, '/etc/turbinia/name.yaml')

  @mock.patch('turbinia.config.RECIPE_FILE_DIR', None, create=True)
  def testGetRecipeFromPathDefault(self):
    """Check recipe path is correct when RECIPE_FILE_DIR is not set."""
    file_path_default = recipe_helpers.get_recipe_path_from_name('name')
    file_name = os.path.basename(file_path_default)
    first_parent_dir = os.path.basename(os.path.dirname(file_path_default))
    second_parent_dir = os.path.basename(
        os.path.dirname(os.path.dirname(file_path_default)))
    self.assertEqual(file_name, 'name.yaml')
    self.assertEqual(first_parent_dir, 'recipes')
    self.assertEqual(second_parent_dir, 'config')
