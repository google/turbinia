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

from datetime import timedelta
import json
import unittest
import importlib
import mock

from turbinia import config
from turbinia import client as TurbiniaClientProvider
from turbinia import TurbiniaException

DATETIME_FORMAT = '%Y-%m-%dT%H:%M:%S.%fZ'


class TestTurbiniaClient(unittest.TestCase):
  """Test Turbinia client class."""

  @mock.patch('turbinia.client.task_manager.PSQTaskManager._backend_setup')
  @mock.patch('google.cloud.datastore.Client')
  def setUp(self, _, __):  #pylint: disable=arguments-differ
    """Initialize tests for Turbinia client."""
    config.LoadConfig()
    config.TASK_MANAGER = 'PSQ'
    config.STATE_MANAGER = 'Datastore'
    config.CLOUD_PROVIDER = 'GCP'

    # Reload module using the config settings above.
    # This is needed due to the conditional imports in client.py
    importlib.reload(TurbiniaClientProvider)
    self.client = TurbiniaClientProvider.get_turbinia_client()
    TurbiniaClientProvider.RETRY_SLEEP = 0.001

  def testTurbiniaClientInit(self):
    """Basic test for client."""
    client = self.client
    self.assertTrue(hasattr(client, 'task_manager'))

  @mock.patch('libcloudforensics.providers.gcp.internal.function.GoogleCloudFunction.ExecuteFunction')  # yapf: disable
  def testTurbiniaClientGetTaskData(self, mock_cloud_function):
    """Basic test for client.get_task_data"""
    # ExecuteFunction returns a dict with a 'result' key that has a json-encoded
    # list.  This contains our task data, which is a list of dicts.
    run_time = timedelta(seconds=3)
    test_task_data = [{'bar': 'bar2', 'run_time': run_time.total_seconds()}]
    gcf_result = [test_task_data, 'Unused GCF data']
    gcf_result = json.dumps(gcf_result)
    function_return = {'result': gcf_result}
    mock_cloud_function.return_value = function_return
    client = self.client
    task_data = client.get_task_data('inst', 'proj', 'reg')
    # get_task_data() converts this back into a timedelta(). We returned it
    # seconds from the GCF function call because that is what it is stored in
    # Datastore as.
    test_task_data[0]['run_time'] = run_time
    self.assertEqual(task_data, test_task_data)

    # Also test that JSON output works
    task_data = client.get_task_data('inst', 'proj', 'reg', output_json=True)
    self.assertEqual(task_data, '[{"bar": "bar2", "run_time": 3.0}]')

  @mock.patch('libcloudforensics.providers.gcp.internal.function.GoogleCloudFunction.ExecuteFunction')  # yapf: disable
  @mock.patch('libcloudforensics.providers.gcp.internal.function.GoogleCloudFunction')  # yapf: disable
  def testTurbiniaClientGetTaskDataNoResults(self, _, mock_cloud_function):
    """Test for exception after empty results from cloud functions."""
    mock_cloud_function.return_value = {}
    client = self.client
    self.assertRaises(
        TurbiniaException, client.get_task_data, "inst", "proj", "reg")

  @mock.patch('libcloudforensics.providers.gcp.internal.function.GoogleCloudFunction.ExecuteFunction')  # yapf: disable
  def testTurbiniaClientGetTaskDataRetriableErrors(self, mock_cloud_function):
    """Test for retries after retriable errors returned from cloud functions."""
    mock_cloud_function.return_value = {'error': {'code': 503}}
    client = self.client
    self.assertRaises(
        TurbiniaException, client.get_task_data, "inst", "proj", "reg")
    self.assertEqual(
        mock_cloud_function.call_count, TurbiniaClientProvider.MAX_RETRIES)

  @mock.patch('libcloudforensics.providers.gcp.internal.function.GoogleCloudFunction.ExecuteFunction')  # yapf: disable
  @mock.patch('libcloudforensics.providers.gcp.internal.function.GoogleCloudFunction')  # yapf: disable
  def testTurbiniaClientGetTaskDataInvalidJson(self, _, mock_cloud_function):
    """Test for exception after bad json results from cloud functions."""
    mock_cloud_function.return_value = {'result': None}
    client = self.client
    self.assertRaises(
        TurbiniaException, client.get_task_data, "inst", "proj", "reg")
