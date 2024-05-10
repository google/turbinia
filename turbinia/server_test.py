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
"""Tests for Turbinia server module."""

import unittest
import mock

from turbinia.server import TurbiniaServer
from turbinia import config


class TestTurbiniaServerPSQ(unittest.TestCase):
  """Test Turbinia Server class."""

  def setUp(self):  #pylint: disable=arguments-differ
    """Initialize tests for Turbinia Server."""
    config.LoadConfig()
    config.STATE_MANAGER = 'Redis'
    config.TASK_MANAGER = 'Celery'

  @mock.patch('turbinia.client.task_manager.CeleryTaskManager._backend_setup')
  @mock.patch('turbinia.state_manager.get_state_manager')
  def testTurbiniaServerInit(self, _, __):
    """Basic test for Turbinia Server init."""
    server = TurbiniaServer()
    self.assertTrue(hasattr(server, 'task_manager'))


class TestTurbiniaServerCelery(unittest.TestCase):
  """Test Turbinia Server class."""

  def setUp(self):  #pylint: disable=arguments-differ
    """Initialize tests for Turbinia Server."""
    config.LoadConfig()
    config.STATE_MANAGER = 'Redis'
    config.TASK_MANAGER = 'Celery'

  @mock.patch('turbinia.client.task_manager.CeleryTaskManager._backend_setup')
  @mock.patch('turbinia.state_manager.get_state_manager')
  def testTurbiniaServerInit(self, _, __):
    """Basic test for Turbinia Server init."""
    server = TurbiniaServer()
    self.assertTrue(hasattr(server, 'task_manager'))
