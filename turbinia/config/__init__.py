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
"""Basic Turbiniaconfig."""

import importlib.util
import importlib.machinery
import itertools
import json
import logging
import os
import sys
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
    'CLOUD_PROVIDER',
    'STATE_MANAGER',
    'TASK_MANAGER',
    'LOG_DIR',
    'LOCK_FILE',
    'TMP_RESOURCE_DIR',
    'RESOURCE_FILE',
    'RESOURCE_FILE_LOCK',
    'SCALEDOWN_WORKER_FILE',
    'OUTPUT_DIR',
    'TMP_DIR',
    'SLEEP_TIME',
    'MOUNT_DIR_PREFIX',
    'SHARED_FILESYSTEM',
    'DEBUG_TASKS',
    'VERSION_CHECK',
    'DEPENDENCIES',
    'DOCKER_ENABLED',
    'DISABLED_JOBS',
    # API SERVER CONFIG
    'API_SERVER_ADDRESS',
    'API_SERVER_PORT',
    'API_ALLOWED_ORIGINS',
    'API_AUTHENTICATION_ENABLED',
    'API_UPLOAD_CHUNK_SIZE',
    'API_EVIDENCE_UPLOAD_DIR',
    'API_MAX_UPLOAD_SIZE',
    'WEBUI_PATH'
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
    'GCS_OUTPUT_PATH',
    'RECIPE_FILE_DIR',
    'STACKDRIVER_TRACEBACK',
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
    # Prometheus config
    'PROMETHEUS_ENABLED',
    'PROMETHEUS_ADDR',
    'PROMETHEUS_PORT',
    # dfDewey config
    'DFDEWEY_PG_HOST',
    'DFDEWEY_PG_PORT',
    'DFDEWEY_PG_DB_NAME',
    'DFDEWEY_OS_HOST',
    'DFDEWEY_OS_PORT',
    'DFDEWEY_OS_URL',
    # General config
    'TURBINIA_COMMAND',
    # API config
    'OIDC_SCOPE',
    'OIDC_KEYS',
    'OIDC_ISSUER',
    'OIDC_VALID_CLIENT_IDS',
    'AUTHORIZED_EMAILS',
    'WEBUI_CLIENT_SECRETS_FILE',
    # LLM Config
    'GCP_GENERATIVE_LANGUAGE_API_KEY',
    'LLM_PROVIDER'
]

# Environment variable to look for path data in
ENVCONFIGVAR = 'TURBINIA_CONFIG_PATH'

CONFIG = None

log = logging.getLogger(__name__)


def LoadConfig(config_file=None):
  """Finds Turbinia config file and loads it.

  Args:
    config_file(str): full path to config file
  """
  # TODO(aarontp): Find way to not require global var here.  Maybe a singleton
  # pattern on the config class.
  # pylint: disable=global-statement
  global CONFIG
  if CONFIG and not config_file:
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

  log.debug(f'Loading config from {config_file:s}')
  # Warn about using fallback source config, but it's currently necessary for
  # tests. See issue #446.
  if 'turbinia_config_tmpl' in config_file:
    log.warning(f'Using fallback source config {CONFIG_MSG:s}')
  try:
    config_loader = importlib.machinery.SourceFileLoader('config', config_file)
    config_spec = importlib.util.spec_from_loader(
        config_loader.name, config_loader)
    _config = importlib.util.module_from_spec(config_spec)
    config_loader.exec_module(_config)
  except IOError as exception:
    message = (f'Could not load config file {config_file:s}: {exception!s}')
    log.error(message)
    raise TurbiniaException(message)

  _config.configSource = config_file
  ValidateAndSetConfig(_config)

  # Set the environment var for this so that we don't see the "No project ID
  # could be determined." warning later.
  if hasattr(_config, 'TURBINIA_PROJECT') and _config.TURBINIA_PROJECT:
    os.environ['GOOGLE_CLOUD_PROJECT'] = _config.TURBINIA_PROJECT

  CONFIG = _config
  log.debug(f'Returning parsed config loaded from {_config.configSource:s}')
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
            f'Setting non-existent but optional config variable {var:s} to None'
        )
        empty_value = True
      else:
        raise TurbiniaException(
            f'Required config attribute {_config.configSource:s}:{var:s} not in config'
        )
    if var in REQUIRED_VARS and getattr(_config, var) is None:
      raise TurbiniaException(
          f'Config attribute {_config.configSource:s}:{var:s} is not set')

    # Set the attribute in the current module
    if empty_value:
      setattr(sys.modules[__name__], var, None)
    else:
      setattr(sys.modules[__name__], var, getattr(_config, var))


def ParseDependencies():
  """Parses the config file DEPENDENCIES variable.

  Raises:
    TurbiniaException: If bad config file.

  Returns:
   dependencies(dict): The parsed dependency values.
  """
  dependencies = {}
  try:
    for values in CONFIG.DEPENDENCIES:
      job = values['job'].lower()
      dependencies[job] = {}
      dependencies[job]['programs'] = values['programs']
      dependencies[job]['docker_image'] = values.get('docker_image')
      dependencies[job]['timeout'] = values.get('timeout')
  except (KeyError, TypeError) as exception:
    raise TurbiniaException(
        f'An issue has occurred while parsing the dependency config: {exception!s}'
    )
  return dependencies


def toDict():
  """Returns a dictionary representing the current config."""
  _config = dict()
  config_vars = REQUIRED_VARS + OPTIONAL_VARS
  config_dict = LoadConfig().__dict__

  for attribute_key in config_dict.keys():
    if attribute_key in config_vars:
      _config[attribute_key] = config_dict[attribute_key]

  return _config
