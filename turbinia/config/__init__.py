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

import imp
import itertools
import os
import sys

# Look for config files with these names
CONFIGFILES = ['.turbiniarc', 'turbinia_config.py']
# Look in homedir and in the current config dir for config files
CONFIGPATH = [os.path.expanduser('~'),
              os.path.dirname(os.path.abspath(__file__))]
# Config vars that we expect to exist in the configuration
CONFIGVARS = [
    'PROJECT',
    'ZONE',
    'INSTANCE',
    'DEVICE_NAME',
    'SCRATCH_PATH',
    'BUCKET_NAME',
]
# Environment variable to look for path data in
ENVCONFIGVAR = 'TURBINIA_CONFIG_PATH'


class TurbiniaConfigException(Exception):
  pass


def LoadConfig():
  """Finds Turbinia config file and loads it."""
  if os.environ.has_key(ENVCONFIGVAR):
    CONFIGPATH.extend(os.environ[ENVCONFIGVAR].split(':'))

  config_file = None
  # Load first file found
  for dir_, file_ in itertools.product(CONFIGPATH, CONFIGFILES):
    if os.path.exists(os.path.join(dir_, file_)):
      config_file = os.path.join(dir_, file_)
      break

  if config_file is None:
    raise TurbiniaConfigException(u'No config files found')

  config_ = imp.load_source('config', config_file)
  config_.configSource = config_file
  ValidateAndSetConfig(config_)
  return config_


def ValidateAndSetConfig(config_):
  """Makes sure that the config has the vars loaded and set in the module."""
  for var in CONFIGVARS:
    if not hasattr(config_, var):
      raise TurbiniaConfigException(
          u'No config attribute {0:s}:{1:s}'.format(config_.configSource, var))
    if getattr(config_, var) is None:
      raise TurbiniaConfigException(
          u'Config attribute {0:s}:{1:s} is not set'.format(
              config_.configSource, var))

    # Set the attribute in the current module
    setattr(sys.modules[__name__], var, getattr(config_, var))
