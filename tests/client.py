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

import mock

from turbinia import config
from turbinia.client import TurbiniaClient
from turbinia.client import TurbiniaServer
from turbinia.client import TurbiniaPsqWorker
from turbinia import TurbiniaException


class TestTurbiniaClient(unittest.TestCase):
  """Test Turbinia client class."""

  @mock.patch('turbinia.client.task_manager.PSQTaskManager.setup')
  def testTurbiniaClientInit(self, _):
    """Basic test for client."""
    config.LoadConfig()
    client = TurbiniaClient()
    self.assertTrue(hasattr(client, 'task_manager'))

  @mock.patch('turbinia.client.GoogleCloudFunction.ExecuteFunction')
  @mock.patch('turbinia.client.task_manager.PSQTaskManager.setup')
  def testTurbiniaClientGetTaskData(self, _, mock_cloud_function):
    """Basic test for client.get_task_data"""
    # ExecuteFunction returns a dict with a 'result' key that has a json-encoded
    # list.
    function_return = {'result': '["bar", "baz"]'}
    mock_cloud_function.return_value = function_return
    client = TurbiniaClient()
    self.assertEqual(client.get_task_data("inst", "proj", "reg"), "bar")

  @mock.patch('turbinia.client.GoogleCloudFunction.ExecuteFunction')
  @mock.patch('turbinia.client.task_manager.PSQTaskManager.setup')
  def testTurbiniaClientGetTaskDataNoResults(self, _, mock_cloud_function):
    """Test for exception after empty results from cloud functions."""
    mock_cloud_function.return_value = {}
    client = TurbiniaClient()
    self.assertRaises(TurbiniaException,
                      client.get_task_data, "inst", "proj", "reg")

  @mock.patch('turbinia.client.GoogleCloudFunction.ExecuteFunction')
  @mock.patch('turbinia.client.task_manager.PSQTaskManager.setup')
  def testTurbiniaClientGetTaskDataInvalidJson(self, _, mock_cloud_function):
    """Test for exception after bad json results from cloud functions."""
    mock_cloud_function.return_value = {'result': None}
    client = TurbiniaClient()
    self.assertRaises(TurbiniaException,
                      client.get_task_data, "inst", "proj", "reg")


class TestTurbiniaServer(unittest.TestCase):
  """Test Turbinia Server class."""

  @mock.patch('turbinia.client.task_manager.PSQTaskManager.setup')
  def testTurbiniaServerInit(self, _):
    """Basic test for Turbinia Server init."""
    server = TurbiniaServer()
    self.assertTrue(hasattr(server, 'task_manager'))


class TestTurbiniaPsqWorker(unittest.TestCase):
  """Test Turbinia PSQ Worker class."""

  @mock.patch('turbinia.client.task_manager.PSQTaskManager')
  @mock.patch('turbinia.client.psq.Worker')
  def testTurbiniaPsqWorkerInit(self, _, __):
    """Basic test for client."""
    worker = TurbiniaPsqWorker()
    self.assertTrue(hasattr(worker, 'worker'))
