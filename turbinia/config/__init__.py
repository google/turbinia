# -*- coding: utf-8 -*-
# Copyright 2016 Google Inc.
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
"""Basic Turbinia config."""

from __future__ import unicode_literals

import imp
import itertools
import logging
import os
import sys
import yaml
from yaml import Loader, load, dump

from turbinia import TurbiniaException

DATETIME_FORMAT = '%Y-%m-%dT%H:%M:%S.%fZ'

# Look for config files with these names
CONFIGFILES = ['.turbiniarc', 'turbinia.conf', 'turbinia_config_tmpl.py']
# Look in homedir first, then /etc/turbinia
CONFIGPATH = [
    os.path.expanduser('~'),
    '/etc/turbinia',
    os.path.dirname(os.path.abspath(__file__)),
]
# Config setup reminder for cleaner error handling on empty configs.
CONFIG_MSG = (
    'Copy turbinia/config/turbinia_config_tmpl.py to ~/.turbiniarc '
    'or /etc/turbinia/turbinia.conf, edit, and re-run.')

# Required config vars
REQUIRED_VARS = [
    # Turbinia Config
    'INSTANCE_ID',
    'STATE_MANAGER',
    'TASK_MANAGER',
    'LOG_FILE',
    'LOCK_FILE',
    'OUTPUT_DIR',
    'TMP_DIR',
    'SLEEP_TIME',
    'SINGLE_RUN',
    'MOUNT_DIR_PREFIX',
    'SHARED_FILESYSTEM',
    # TODO(aarontp): Move this to the recipe config when it's available.
    'DEBUG_TASKS',
    'DEPENDENCIES',
    'DOCKER_ENABLED',
    'DISABLED_JOBS',
]

# Optional config vars.  Some may be mandatory depending on the configuration
# (e.g. if TASK_MANAGER is set to 'PSQ', then the GCE Config variables are
# required), but these requirements are not enforced.
OPTIONAL_VARS = [
    # GCE CONFIG
    'TURBINIA_PROJECT',
    'TURBINIA_ZONE',
    'TURBINIA_REGION',
    'BUCKET_NAME',
    'PSQ_TOPIC',
    'PUBSUB_TOPIC',
    'GCS_OUTPUT_PATH',
    'RECIPE_FILE_DIR',
    # REDIS CONFIG
    'REDIS_HOST',
    'REDIS_PORT',
    'REDIS_DB',
    # Celery config
    'CELERY_BROKER',
    'CELERY_BACKEND',
    'KOMBU_BROKER',
    'KOMBU_CHANNEL',
    'KOMBU_DURABLE',
    # Email config
    'EMAIL_NOTIFICATIONS',
    'EMAIL_HOST_ADDRESS',
    'EMAIL_PORT',
    'EMAIL_ADDRESS',
    'EMAIL_PASSWORD',
    # Recipe Config
    'BASE_TASK_CONFIG_FILE',
]

# Environment variable to look for path data in
ENVCONFIGVAR = 'TURBINIA_CONFIG_PATH'

CONFIG = None

log = logging.getLogger('turbinia')


def LoadConfig(config_file=None):
  """Finds Turbinia config file and loads it.

  Args:
    config_file(str): full path to config file
  """
  # TODO(aarontp): Find way to not require global var here.  Maybe a singleton
  # pattern on the config class.
  # pylint: disable=global-statement
  global CONFIG
  if CONFIG:
    log.debug(
        'Returning cached config from {0:s} instead of reloading config'.format(
            CONFIG.configSource))
    return CONFIG

  if not config_file:
    log.debug('No config specified. Looking in default locations for config.')
    # If the environment variable is set, take precedence over the pre-defined
    # CONFIGPATHs.
    configpath = CONFIGPATH
    if ENVCONFIGVAR in os.environ:
      configpath = os.environ[ENVCONFIGVAR].split(':')

    # Load first file found
    for _dir, _file in itertools.product(configpath, CONFIGFILES):
      if os.path.exists(os.path.join(_dir, _file)):
        config_file = os.path.join(_dir, _file)
        break

  if config_file is None:
    raise TurbiniaException('No config files found')

  log.debug('Loading config from {0:s}'.format(config_file))
  # Warn about using fallback source config, but it's currently necessary for
  # tests. See issue #446.
  if 'turbinia_config_tmpl' in config_file:
    log.warning('Using fallback source config. {0:s}'.format(CONFIG_MSG))
  try:
    _config = imp.load_source('config', config_file)
  except IOError as exception:
    message = (
        'Could not load config file {0:s}: {1!s}'.format(
            config_file, exception))
    log.error(message)
    raise TurbiniaException(message)

  _config.configSource = config_file
  ValidateAndSetConfig(_config)

  # Set the environment var for this so that we don't see the "No project ID
  # could be determined." warning later.
  if hasattr(_config, 'TURBINIA_PROJECT') and _config.TURBINIA_PROJECT:
    os.environ['GOOGLE_CLOUD_PROJECT'] = _config.TURBINIA_PROJECT

  CONFIG = _config
  log.debug(
      'Returning parsed config loaded from {0:s}'.format(CONFIG.configSource))
  return _config


def ValidateAndSetConfig(_config):
  """Makes sure that the config has the vars loaded and set in the module."""
  # Explicitly set the config path
  setattr(sys.modules[__name__], 'configSource', _config.configSource)

  CONFIGVARS = REQUIRED_VARS + OPTIONAL_VARS
  for var in CONFIGVARS:
    empty_value = False
    if not hasattr(_config, var):
      if var in OPTIONAL_VARS:
        log.debug(
            'Setting non-existent but optional config variable {0:s} to '
            'None'.format(var))
        empty_value = True
      else:
        raise TurbiniaException(
            'Required config attribute {0:s}:{1:s} not in config'.format(
                _config.configSource, var))
    if var in REQUIRED_VARS and getattr(_config, var) is None:
      raise TurbiniaException(
          'Config attribute {0:s}:{1:s} is not set'.format(
              _config.configSource, var))

    # Set the attribute in the current module
    if empty_value:
      setattr(sys.modules[__name__], var, None)
    else:
      setattr(sys.modules[__name__], var, getattr(_config, var))


class TurbiniaRecipe(object):
  """ Base class for Turbinia recipes

  Attributes
      recipe_file (str): name of the recipe file to be loaded.
      jobs_whitelist (list): A whitelist for Jobs that will be allowed to run.
      jobs_blacklist (list): A blacklist for Jobs that will not be
      allowed to run.
      filter_patterns_file (str): Path to a file containing newline separated
      string patterns with which to filter text based evidence.
      task_recipes (dict): Object containing a task specific recipe for
      each of the tasks invoked in the Turbinia recipe.
"""

  def __init__(self, recipe_file, filter_patterns_files=[]):
    self.recipe_file = recipe_file
    self.filter_patterns_files = (
        filter_patterns_files if filter_patterns_files else [])

    self.name = ""
    self.jobs_whitelist = []
    self.jobs_blacklist = []
    self.filter_patterns = []
    self.task_recipes = {}

  def load(self):
    """ Load recipe from file. """
    LoadConfig()
    with open(self.recipe_file, 'r') as r_file:
      try:
        recipe_contents = r_file.read()
      except yaml.parser.ParserError as exception:
        message = (
            'Could not load recipe file {0:s}: {1!s}'.format(
                self.recipe_file, exception))
        log.error(message)
        raise TurbiniaException(message)
    recipe_dict = load(recipe_contents, Loader=Loader)
    self.jobs_whitelist = recipe_dict.get('jobs_whitelist', [])
    self.jobs_blacklist = recipe_dict.get('jobs_blacklist', [])
    for _file in self.filter_patterns_files:
      with open(_file) as pattern_file:
        line = pattern_file.readline()
        if line not in self.filter_patterns:
          self.filter_patterns.append(line)
    for recipe_item, item_contents in recipe_dict.items():
      if (recipe_item not in
          ['jobs_blacklist', 'jobs_whitelist', 'filter_patterns_files']):
        aux_task_recipe = TurbiniaTaskRecipe(recipe_item)
        aux_task_recipe.load(item_contents)
        if recipe_item in self.task_recipes:
          raise TurbiniaException(
              'Two recipes for the same tool {0:s} have been found.'
              'If you wish to specify several task runs of the same tools,'
              'please add several task variants to the same tool recipe.'
          )
        self.task_recipes[recipe_item] = aux_task_recipe

  def retrieve_task_recipe(self, task):
    """ Retrieve recipe by name.  """
    if task in self.task_recipes:
      return self.task_recipes[task]

  def serialize(self):
    """ Obtain serialized task recipe dict. """
    serialized_data = self.__dict__.copy()
    serialized_data['task_recipes'] = {
        k: v.serialize() for k, v in self.task_recipes.items()
    }
    return serialized_data


class TurbiniaTaskRecipe(object):
  """ Base class for task recipe container. """

  def __init__(self, name):
    self.name = name
    self.variants = {}

  def load(self, data):
    """ Load task recipe from dict """

    if 'variants' not in data:
      data['variants'] = {'single_variant': data}
    for variant, variant_config in data['variants'].items():
      aux_variant = TaskRecipeVariant(name=variant)
      aux_variant.load(variant_config)
      self.variants[variant] = aux_variant

  def serialize(self):
    """ Serialize task tecipe into dict. """
    serialized_data = {}
    serialized_data['name'] = self.name
    serialized_data['variants'] = {
        k: v.__dict__ for k, v in self.variants.items()
    }
    return serialized_data


class TaskRecipeVariant(object):
  """ Class to house an instance of a task recipe """

  def __init__(self, name):
    self.name = name
    self.params = None

  def load(self, data):
    """ Load task recipe intance from dict. """
    self.params = data['params'] if 'params' in data else {}
