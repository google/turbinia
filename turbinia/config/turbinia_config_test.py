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
"""Tests for Turbinia config."""

from __future__ import unicode_literals

import os
import tempfile
import unittest

from turbinia import config
from turbinia import TurbiniaException


class TestTurbiniaConfig(unittest.TestCase):
  """Tests for the Turbinia configuration module."""

  @classmethod
  def setUpClass(cls):
    # Remove the loaded attributes because the module is loaded before the
    # tests start by turbinia __init__.
    # pylint: disable=expression-not-assigned
    config_vars = config.REQUIRED_VARS + config.OPTIONAL_VARS
    [delattr(config, a) for a in config_vars if hasattr(config, a)]
    cls.CONFIGPATH_SAVE = config.CONFIGPATH
    cls.CONFIGFILES_SAVE = config.CONFIGFILES
    cls.REQUIRED_VARS_SAVE = config.REQUIRED_VARS
    cls.OPTIONAL_VARS_SAVE = config.OPTIONAL_VARS

  def setUp(self):
    # Record the module attributes so we can remove them after the test to
    # simulate a reload() since it's non-trivial to remove/import the module
    # when it has a other references.
    self.config_attrs = dir(config)
    self.config_file = tempfile.mkstemp()[1]
    config.CONFIG = None
    config.CONFIGPATH = [os.path.dirname(self.config_file)]
    config.CONFIGFILES = [os.path.basename(self.config_file)]
    config.REQUIRED_VARS = []
    config.OPTIONAL_VARS = []

  @classmethod
  def tearDownClass(cls):
    """Called after tests in the class have been run."""
    config.CONFIGPATH = cls.CONFIGPATH_SAVE
    config.CONFIGFILES = cls.CONFIGFILES_SAVE
    config.REQUIRED_VARS = cls.REQUIRED_VARS_SAVE
    config.OPTIONAL_VARS = cls.OPTIONAL_VARS_SAVE

  def tearDown(self):
    os.remove(self.config_file)
    # Remove the added module attributes
    # pylint: disable=expression-not-assigned
    [delattr(config, a) for a in dir(config) if a not in self.config_attrs]
    config.CONFIG = None

  def WriteConfig(self, text, config_file=None):
    """Helper to write text to a configuration file.

    Args:
      text (str): data to write to the file.
      config_file(str): Alternate path to write config file to.
    """
    if not config_file:
      config_file = self.config_file
    with open(config_file, 'w') as config_file_handle:
      config_file_handle.write(text)

  def testBasicConfig(self):
    """Test out a basic config."""
    self.WriteConfig('TURBINIA_PROJECT = "foo"\nTURBINIA_ZONE = "bar"\n')
    config.REQUIRED_VARS = ['TURBINIA_PROJECT', 'TURBINIA_ZONE']
    self.assertFalse(hasattr(config, 'TURBINIA_PROJECT'))
    config.LoadConfig()
    self.assertTrue(hasattr(config, 'TURBINIA_PROJECT'))
    self.assertTrue(hasattr(config, 'TURBINIA_ZONE'))
    self.assertEqual(config.TURBINIA_PROJECT, 'foo')
    self.assertEqual(config.TURBINIA_ZONE, 'bar')

  def testMissingRequiredKeyConfig(self):
    """Test that config errors out when not all required variables exist."""
    self.WriteConfig('EXISTS = "bar"\n')
    config.REQUIRED_VARS = ['DOESNOTEXIST', 'EXISTS']
    self.assertRaises(TurbiniaException, config.LoadConfig)

  def testUnsetRequiredKeyConfig(self):
    """Test that config errors out when not all required variables are set."""
    self.WriteConfig('UNSETKEY = None\nSETKEY = "bar"\n')
    config.REQUIRED_VARS = ['UNSETKEY', 'SETKEY']
    self.assertRaises(TurbiniaException, config.LoadConfig)

  def testUnsetOptionalKeyConfig(self):
    """Test that optional vars don't need to be set."""
    self.WriteConfig('UNSETKEY = None\nSETKEY = "bar"\n')
    config.REQUIRED_VARS = ['SETKEY']
    config.OPTIONAL_VARS = ['UNSETKEY']
    config.LoadConfig()
    self.assertEqual(config.UNSETKEY, None)
    self.assertEqual(config.SETKEY, 'bar')

  def testNonexistentOptionalKeyConfig(self):
    """Test that optional vars don't need to exist."""
    self.WriteConfig('SETKEY = "bar"\n')
    config.REQUIRED_VARS = ['SETKEY']
    config.OPTIONAL_VARS = ['UNSETKEY']
    config.LoadConfig()
    self.assertEqual(config.UNSETKEY, None)
    self.assertEqual(config.SETKEY, 'bar')

  def testMissingConfigPath(self):
    """Test non-existent config path."""
    config.CONFIGPATH = ['DOESNOTEXIST']
    self.assertRaises(TurbiniaException, config.LoadConfig)

  def testMissingConfigFile(self):
    """Test non-existent config file."""
    self.assertRaises(TurbiniaException, config.LoadConfig, '/does/not/exist')

  def testExplicitConfigPath(self):
    """Test setting direct config file path."""
    config_file = tempfile.mkstemp()[1]
    config.REQUIRED_VARS = ['KEY', 'EX']
    # Write to default config file
    self.WriteConfig('KEY = "oldkey"\nEX = "bar"\n')
    # write to explicit config file
    self.WriteConfig('KEY = "newkey"\nEX = "bar"\n', config_file=config_file)
    config.LoadConfig(config_file=config_file)
    # Make sure the config data is from the specified file and not the default
    self.assertEqual(config.KEY, 'newkey')
    os.remove(config_file)

  def testEnvPathConfig(self):
    """Test that config path can be read from the environment."""
    os.environ[config.ENVCONFIGVAR] = config.CONFIGPATH[0]
    config.CONFIGPATH = ['DOESNOTEXIST']

    self.WriteConfig('TURBINIA_PROJECT = "foo"\nTURBINIA_ZONE = "bar"\n')
    config.REQUIRED_VARS = ['TURBINIA_PROJECT', 'TURBINIA_ZONE']
    config.LoadConfig()
    self.assertTrue(hasattr(config, 'TURBINIA_PROJECT'))
    self.assertTrue(hasattr(config, 'TURBINIA_ZONE'))
    self.assertEqual(config.TURBINIA_PROJECT, 'foo')
    self.assertEqual(config.TURBINIA_ZONE, 'bar')
    os.environ.pop(config.ENVCONFIGVAR)

  def testParseDependencies(self):
    """Tests a valid config for the ParseDependencies() method."""
    smpl_depends = 'DEPENDENCIES = [{"job": "PlasoJob","programs": ["test"], \
                   "docker_image": "test", "timeout":30}]'

    self.WriteConfig(smpl_depends)
    config.LoadConfig()
    smpl_out = {
        'plasojob': {
            'programs': ['test'],
            'docker_image': 'test',
            'timeout': 30
        }
    }
    smpl_test = config.ParseDependencies()
    self.assertEqual(smpl_out, smpl_test)

  def testBadDependenciesConfig(self):
    """Tests a bad config for the ParseDependencies() method."""
    bad_config = 'DEPENDENCIES = [{"bad_config"}]'
    self.WriteConfig(bad_config)
    config.LoadConfig()
    self.assertRaises(TurbiniaException, config.ParseDependencies)
