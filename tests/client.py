# -*- coding: utf-8 -*-
# Copyright 2018 Google Inc.
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
"""Tests for Turbinia client module."""

from __future__ import unicode_literals

import unittest

import json
import mock

from turbinia import config
from turbinia.client import TurbiniaClient
from turbinia.client import TurbiniaServer
from turbinia.client import TurbiniaPsqWorker
from turbinia import TurbiniaException


class TestTurbiniaClient(unittest.TestCase):
  """Test Turbinia client class."""

  def testTurbiniaClientInit(self):
    """Basic test for client."""
    config.LoadConfig()
    client = TurbiniaClient()
    self.assertTrue(hasattr(client, 'task_manager_'))

  @mock.patch('turbinia.client.GoogleCloudFunction.ExecuteFunction')
  def testTurbiniaClientGetTaskData(self, mock_cloud_function):
    """Basic test for client.get_task_data"""
    # ExecuteFunction returns a dict with a 'result' key that has a json-encoded
    # list.
    function_return = {'result': '["bar", "baz"]'}
    mock_cloud_function.return_value = function_return
    client = TurbiniaClient()
    self.assertEqual(client.get_task_data("inst", "proj", "reg"), "bar")

  def testTurbiniaClientGetTaskDataNoResults(self, mock_cloud_function):
    pass

  def testTurbiniaClientGetTaskDataInvalidJson(self, mock_cloud_function):
    pass


class TestTurbiniaServer(unittest.TestCase):
  """Test Turbinia Server class."""

  def testTurbiniaServerInit(self):
    """Basic test for Turbinia Server init."""
    server = TurbiniaServer()
    self.assertTrue(hasattr(server, 'task_manager_'))


class TestTurbiniaPsqWorker(unittest.TestCase):
  """Test Turbinia PSQ Worker class."""

  def testTurbiniaPsqWorkerInit(self):
    """Basic test for client."""
    worker = TurbiniaPsqWorker()
    self.assertTrue(hasattr(worker, 'worker'))
