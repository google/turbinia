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

from datetime import datetime
import unittest
import os
import shutil
import tempfile
import textwrap

import mock

from turbinia import config
from turbinia.client import TurbiniaClient
from turbinia.client import TurbiniaServer
from turbinia.client import TurbiniaPsqWorker
from turbinia import TurbiniaException

SHORT_REPORT = textwrap.dedent(
    """\
    # Turbinia report 0xFakeRequestId
    * Processed 3 Tasks for user myuser
    
    # High Priority Tasks
    * TaskName2: This second fake task executed
    
    # Successful Tasks
    * TaskName: This fake task executed
    
    # Failed Tasks
    * TaskName3: Third Task Failed...
    
    # Scheduled or Running Tasks
    * None
""")

LONG_REPORT = textwrap.dedent(
    """\
    # Turbinia report 0xFakeRequestId
    * Processed 3 Tasks for user myuser
    
    # High Priority Tasks
    ## TaskName2
    * **Status:** This second fake task executed
    * Task Id: 0xfakeTaskId2
    * Executed on worker fake_worker
    
    ### Task Reported Data
    #### Fake High priority Report
    * Fake Bullet
    
    # Successful Tasks
    * TaskName: This fake task executed
    
    # Failed Tasks
    * TaskName3: Third Task Failed...
    
    # Scheduled or Running Tasks
    * None
""")

LONG_REPORT_FILES = textwrap.dedent(
    """\
    # Turbinia report 0xFakeRequestId
    * Processed 3 Tasks for user myuser
    
    # High Priority Tasks
    ## TaskName2
    * **Status:** This second fake task executed
    * Task Id: 0xfakeTaskId2
    * Executed on worker fake_worker
    
    ### Task Reported Data
    #### Fake High priority Report
    * Fake Bullet
    
    ### Saved Task Files:
    * `/no/path/2`
    * `/fake/path/2`

    
    # Successful Tasks
    * TaskName: This fake task executed
        * `/no/path/`
        * `/fake/path`

    
    # Failed Tasks
    * TaskName3: Third Task Failed...
        * `/no/path/3`
        * `/fake/path/3`

    
    # Scheduled or Running Tasks
    * None
""")


class TestTurbiniaClient(unittest.TestCase):
  """Test Turbinia client class."""

  def setUp(self):
    self.task_data = [
        {
            'id': '0xfakeTaskId',
            'instance': 'MyTurbiniaInstance',
            'last_update': datetime.now(),
            'name': 'TaskName',
            'report_data': '#### Fake Low priority Report\n* Fake Bullet',
            'report_priority': 80,
            'request_id': '0xFakeRequestId',
            'saved_paths': ['/no/path/', '/fake/path'],
            'status': 'This fake task executed',
            'successful': True,
            'user': 'myuser',
            'worker_name': 'fake_worker'
        }, {
            'id': '0xfakeTaskId2',
            'instance': 'MyTurbiniaInstance',
            'last_update': datetime.now(),
            'name': 'TaskName2',
            'report_data': '#### Fake High priority Report\n* Fake Bullet',
            'report_priority': 10,
            'request_id': '0xFakeRequestId',
            'saved_paths': ['/no/path/2', '/fake/path/2'],
            'status': 'This second fake task executed',
            'successful': True,
            'user': 'myuser',
            'worker_name': 'fake_worker'
        }, {
            'id': '0xfakeTaskId3',
            'instance': 'MyTurbiniaInstance',
            'last_update': datetime.now(),
            'name': 'TaskName3',
            'report_data': '',
            'report_priority': 80,
            'request_id': '0xFakeRequestId',
            'saved_paths': ['/no/path/3', '/fake/path/3'],
            'status': 'Third Task Failed...',
            'successful': False,
            'user': 'myuser',
            'worker_name': 'fake_worker'
        }
    ] # yapf: disable


  @mock.patch('turbinia.client.task_manager.PSQTaskManager._backend_setup')
  @mock.patch('turbinia.state_manager.get_state_manager')
  def testTurbiniaClientInit(self, _, __):
    """Basic test for client."""
    config.LoadConfig()
    client = TurbiniaClient()
    self.assertTrue(hasattr(client, 'task_manager'))

  @mock.patch('turbinia.client.GoogleCloudFunction.ExecuteFunction')
  @mock.patch('turbinia.client.task_manager.PSQTaskManager._backend_setup')
  @mock.patch('turbinia.state_manager.get_state_manager')
  def testTurbiniaClientGetTaskData(self, _, __, mock_cloud_function):
    """Basic test for client.get_task_data"""
    # ExecuteFunction returns a dict with a 'result' key that has a json-encoded
    # list.
    function_return = {'result': '["bar", "baz"]'}
    mock_cloud_function.return_value = function_return
    client = TurbiniaClient()
    self.assertEqual(client.get_task_data("inst", "proj", "reg"), "bar")

  @mock.patch('turbinia.client.GoogleCloudFunction.ExecuteFunction')
  @mock.patch('turbinia.client.task_manager.PSQTaskManager._backend_setup')
  @mock.patch('turbinia.state_manager.get_state_manager')
  def testTurbiniaClientGetTaskDataNoResults(self, _, __, mock_cloud_function):
    """Test for exception after empty results from cloud functions."""
    mock_cloud_function.return_value = {}
    client = TurbiniaClient()
    self.assertRaises(
        TurbiniaException, client.get_task_data, "inst", "proj", "reg")

  @mock.patch('turbinia.client.GoogleCloudFunction.ExecuteFunction')
  @mock.patch('turbinia.client.task_manager.PSQTaskManager._backend_setup')
  @mock.patch('turbinia.state_manager.get_state_manager')
  def testTurbiniaClientGetTaskDataInvalidJson(
      self, _, __, mock_cloud_function):
    """Test for exception after bad json results from cloud functions."""
    mock_cloud_function.return_value = {'result': None}
    client = TurbiniaClient()
    self.assertRaises(
        TurbiniaException, client.get_task_data, "inst", "proj", "reg")

  @mock.patch('turbinia.client.GoogleCloudFunction.ExecuteFunction')
  @mock.patch('turbinia.client.task_manager.PSQTaskManager._backend_setup')
  @mock.patch('turbinia.state_manager.get_state_manager')
  def testClientFormatTaskStatus(self, _, __, ___):
    """Tests format_task_status() has valid output."""
    client = TurbiniaClient()
    client.get_task_data = mock.MagicMock()
    client.get_task_data.return_value = self.task_data
    result = client.format_task_status('inst', 'proj', 'reg')
    self.assertEqual(result.strip(), SHORT_REPORT.strip())

  @mock.patch('turbinia.client.GoogleCloudFunction.ExecuteFunction')
  @mock.patch('turbinia.client.task_manager.PSQTaskManager._backend_setup')
  @mock.patch('turbinia.state_manager.get_state_manager')
  def testClientFormatTaskStatusFullReport(self, _, __, ___):
    """Tests format_task_status() has valid output with full report."""
    client = TurbiniaClient()
    client.get_task_data = mock.MagicMock()
    client.get_task_data.return_value = self.task_data
    result = client.format_task_status('inst', 'proj', 'reg', full_report=True)
    self.assertEqual(result.strip(), LONG_REPORT.strip())

  @mock.patch('turbinia.client.GoogleCloudFunction.ExecuteFunction')
  @mock.patch('turbinia.client.task_manager.PSQTaskManager._backend_setup')
  @mock.patch('turbinia.state_manager.get_state_manager')
  def testClientFormatTaskStatusFiles(self, _, __, ___):
    """Tests format_task_status() has valid output with report and files."""
    client = TurbiniaClient()
    client.get_task_data = mock.MagicMock()
    client.get_task_data.return_value = self.task_data
    result = client.format_task_status(
        'inst', 'proj', 'reg', all_fields=True, full_report=True)
    self.assertEqual(result.strip(), LONG_REPORT_FILES.strip())


class TestTurbiniaServer(unittest.TestCase):
  """Test Turbinia Server class."""

  @mock.patch('turbinia.client.task_manager.PSQTaskManager._backend_setup')
  @mock.patch('turbinia.state_manager.get_state_manager')
  def testTurbiniaServerInit(self, _, __):
    """Basic test for Turbinia Server init."""
    server = TurbiniaServer()
    self.assertTrue(hasattr(server, 'task_manager'))


class TestTurbiniaPsqWorker(unittest.TestCase):
  """Test Turbinia PSQ Worker class."""

  def setUp(self):
    self.tmp_dir = tempfile.mkdtemp(prefix='turbinia-test')
    config.LoadConfig()
    config.OUTPUT_DIR = self.tmp_dir
    config.MOUNT_DIR_PREFIX = self.tmp_dir

  def tearDown(self):
    if 'turbinia-test' in self.tmp_dir:
      shutil.rmtree(self.tmp_dir)

  @mock.patch('turbinia.client.pubsub')
  @mock.patch('turbinia.client.datastore.Client')
  @mock.patch('turbinia.client.psq.Worker')
  def testTurbiniaPsqWorkerInit(self, _, __, ___):
    """Basic test for PSQ worker."""
    worker = TurbiniaPsqWorker()
    self.assertTrue(hasattr(worker, 'worker'))

  @mock.patch('turbinia.client.pubsub')
  @mock.patch('turbinia.client.datastore.Client')
  @mock.patch('turbinia.client.psq.Worker')
  def testTurbiniaClientNoDir(self, _, __, ___):
    """Test that OUTPUT_DIR path is created."""
    config.OUTPUT_DIR = os.path.join(self.tmp_dir, 'no_such_dir')
    TurbiniaPsqWorker()
    self.assertTrue(os.path.exists(config.OUTPUT_DIR))

  @mock.patch('turbinia.client.pubsub')
  @mock.patch('turbinia.client.datastore.Client')
  @mock.patch('turbinia.client.psq.Worker')
  def testTurbiniaClientIsNonDir(self, _, __, ___):
    """Test that OUTPUT_DIR does not point to an existing non-directory."""
    config.OUTPUT_DIR = os.path.join(self.tmp_dir, 'empty_file')
    open(config.OUTPUT_DIR, 'a').close()
    self.assertRaises(TurbiniaException, TurbiniaPsqWorker)
