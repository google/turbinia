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

from __future__ import unicode_literals

import unittest
import mock

from turbinia.server import TurbiniaServer


class TestTurbiniaServer(unittest.TestCase):
  """Test Turbinia Server class."""

  @mock.patch('turbinia.client.task_manager.PSQTaskManager._backend_setup')
  @mock.patch('turbinia.state_manager.get_state_manager')
  def testTurbiniaServerInit(self, _, __):
    """Basic test for Turbinia Server init."""
    server = TurbiniaServer()
    self.assertTrue(hasattr(server, 'task_manager'))