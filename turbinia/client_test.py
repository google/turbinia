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
from datetime import timedelta
import json
import unittest
import os
import shutil
import tempfile
import textwrap

import mock

from turbinia import config
from turbinia.client import TurbiniaClient
from turbinia.client import TurbiniaServer
from turbinia.client import TurbiniaStats
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
    * Executed on worker fake_worker2

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
    * Executed on worker fake_worker2

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

STATISTICS_REPORT = textwrap.dedent(
    """\
    Execution time statistics for Turbinia:

    All Tasks: Count: 3, Min: 0:01:00, Mean: 0:03:00, Max: 0:05:00
    Successful Tasks: Count: 2, Min: 0:01:00, Mean: 0:05:00, Max: 0:05:00
    Failed Tasks: Count: 1, Min: 0:03:00, Mean: 0:03:00, Max: 0:03:00
    Total Request Time: Count: 2, Min: 0:03:00, Mean: 0:21:00, Max: 0:21:00
    Task type TaskName: Count: 1, Min: 0:01:00, Mean: 0:01:00, Max: 0:01:00
    Task type TaskName2: Count: 1, Min: 0:05:00, Mean: 0:05:00, Max: 0:05:00
    Task type TaskName3: Count: 1, Min: 0:03:00, Mean: 0:03:00, Max: 0:03:00
    Worker fake_worker: Count: 2, Min: 0:01:00, Mean: 0:03:00, Max: 0:03:00
    Worker fake_worker2: Count: 1, Min: 0:05:00, Mean: 0:05:00, Max: 0:05:00
    User myuser: Count: 2, Min: 0:01:00, Mean: 0:05:00, Max: 0:05:00
    User myuser2: Count: 1, Min: 0:03:00, Mean: 0:03:00, Max: 0:03:00
""")

STATISTICS_REPORT_CSV = textwrap.dedent(
    """\
    stat_type, count, min, mean, max
    All Tasks, 3, 0:01:00, 0:03:00, 0:05:00
    Successful Tasks, 2, 0:01:00, 0:05:00, 0:05:00
    Failed Tasks, 1, 0:03:00, 0:03:00, 0:03:00
    Total Request Time, 2, 0:03:00, 0:21:00, 0:21:00
    Task type TaskName, 1, 0:01:00, 0:01:00, 0:01:00
    Task type TaskName2, 1, 0:05:00, 0:05:00, 0:05:00
    Task type TaskName3, 1, 0:03:00, 0:03:00, 0:03:00
    Worker fake_worker, 2, 0:01:00, 0:03:00, 0:03:00
    Worker fake_worker2, 1, 0:05:00, 0:05:00, 0:05:00
    User myuser, 2, 0:01:00, 0:05:00, 0:05:00
    User myuser2, 1, 0:03:00, 0:03:00, 0:03:00
""")


class TestTurbiniaClient(unittest.TestCase):
  """Test Turbinia client class."""

  def setUp(self):
    last_update = datetime.now()
    self.task_data = [
        {
            'id': '0xfakeTaskId',
            'instance': 'MyTurbiniaInstance',
            'last_update': last_update,
            'name': 'TaskName',
            'report_data': '#### Fake Low priority Report\n* Fake Bullet',
            'report_priority': 80,
            'request_id': '0xFakeRequestId',
            'run_time': timedelta(minutes=1),
            'saved_paths': ['/no/path/', '/fake/path'],
            'status': 'This fake task executed',
            'successful': True,
            'requester': 'myuser',
            'worker_name': 'fake_worker'
        }, {
            'id': '0xfakeTaskId2',
            'instance': 'MyTurbiniaInstance',
            'last_update': last_update + timedelta(minutes=20),
            'name': 'TaskName2',
            'report_data': '#### Fake High priority Report\n* Fake Bullet',
            'report_priority': 10,
            'request_id': '0xFakeRequestId',
            'run_time': timedelta(minutes=5),
            'saved_paths': ['/no/path/2', '/fake/path/2'],
            'status': 'This second fake task executed',
            'successful': True,
            'requester': 'myuser',
            'worker_name': 'fake_worker2'
        }, {
            'id': '0xfakeTaskId3',
            'instance': 'MyTurbiniaInstance',
            'last_update': last_update,
            'name': 'TaskName3',
            'report_data': '',
            'report_priority': 80,
            'request_id': '0xFakeRequestId2',
            'run_time': timedelta(minutes=3),
            'saved_paths': ['/no/path/3', '/fake/path/3'],
            'status': 'Third Task Failed...',
            'successful': False,
            'requester': 'myuser2',
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
    # list.  This contains our task data, which is a list of dicts.
    run_time = timedelta(seconds=3)
    test_task_data = [{'bar': 'bar2', 'run_time': run_time.total_seconds()}]
    gcf_result = [test_task_data, 'Unused GCF data']
    gcf_result = json.dumps(gcf_result)
    function_return = {'result': gcf_result}
    mock_cloud_function.return_value = function_return
    client = TurbiniaClient()
    task_data = client.get_task_data('inst', 'proj', 'reg')
    # get_task_data() converts this back into a timedelta(). We returned it
    # seconds from the GCF function call because that is what it is stored in
    # Datastore as.
    test_task_data[0]['run_time'] = run_time
    self.assertEqual(task_data, test_task_data)

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
  def testClientFormatTaskStatistics(self, _, __, ___):
    """Tests format_task_statistics() report output."""
    client = TurbiniaClient()
    client.get_task_data = mock.MagicMock()
    client.get_task_data.return_value = self.task_data
    stats_report = client.format_task_statistics('inst', 'proj', 'reg')
    self.maxDiff = None
    self.assertEqual(stats_report, STATISTICS_REPORT)

  @mock.patch('turbinia.client.GoogleCloudFunction.ExecuteFunction')
  @mock.patch('turbinia.client.task_manager.PSQTaskManager._backend_setup')
  @mock.patch('turbinia.state_manager.get_state_manager')
  def testClientFormatTaskStatisticsCsv(self, _, __, ___):
    """Tests format_task_statistics() CSV report output."""
    client = TurbiniaClient()
    client.get_task_data = mock.MagicMock()
    client.get_task_data.return_value = self.task_data
    stats_report = client.format_task_statistics(
        'inst', 'proj', 'reg', csv=True)
    self.maxDiff = None
    self.assertEqual(stats_report, STATISTICS_REPORT_CSV)

  @mock.patch('turbinia.client.GoogleCloudFunction.ExecuteFunction')
  @mock.patch('turbinia.client.task_manager.PSQTaskManager._backend_setup')
  @mock.patch('turbinia.state_manager.get_state_manager')
  def testClientGetTaskStatistics(self, _, __, ___):
    """Tests get_task_statistics() basic functionality."""
    client = TurbiniaClient()
    client.get_task_data = mock.MagicMock()
    client.get_task_data.return_value = self.task_data
    task_stats = client.get_task_statistics('inst', 'proj', 'reg')

    # Make sure we have the right number of tasks for all sections
    self.assertEqual(task_stats['all_tasks'].count, 3)
    self.assertEqual(task_stats['successful_tasks'].count, 2)
    self.assertEqual(task_stats['failed_tasks'].count, 1)
    self.assertEqual(task_stats['requests'].count, 2)
    self.assertEqual(len(task_stats['tasks_per_user']), 2)
    self.assertEqual(len(task_stats['tasks_per_worker']), 2)
    self.assertEqual(len(task_stats['tasks_per_type']), 3)

    # Checking min/mean/max
    self.assertEqual(task_stats['all_tasks'].min, timedelta(minutes=1))
    self.assertEqual(task_stats['all_tasks'].mean, timedelta(minutes=3))
    self.assertEqual(task_stats['all_tasks'].max, timedelta(minutes=5))
    # Delta for this is 21 minutes because the last_update for 0xfakeTaskId2 is
    # 20 minutes later than the first task, and the first task ran for 1 minute.
    self.assertEqual(task_stats['requests'].max, timedelta(minutes=21))
    self.assertEqual(
        task_stats['tasks_per_user']['myuser'].max, timedelta(minutes=5))
    self.assertEqual(
        task_stats['tasks_per_worker']['fake_worker'].max, timedelta(minutes=3))
    self.assertEqual(
        task_stats['tasks_per_type']['TaskName2'].mean, timedelta(minutes=5))

  @mock.patch('turbinia.client.GoogleCloudFunction.ExecuteFunction')
  @mock.patch('turbinia.client.task_manager.PSQTaskManager._backend_setup')
  @mock.patch('turbinia.state_manager.get_state_manager')
  def testClientFormatTaskStatus(self, _, __, ___):
    """Tests format_task_status() with empty report_priority."""
    client = TurbiniaClient()
    client.get_task_data = mock.MagicMock()
    self.task_data[0]['report_priority'] = None
    self.task_data[1]['report_priority'] = ''
    self.task_data[2].pop('report_priority')
    client.get_task_data.return_value = self.task_data
    result = client.format_task_status('inst', 'proj', 'reg')
    self.assertIn('Processed 3 Tasks', result.strip())

  @mock.patch('turbinia.client.GoogleCloudFunction.ExecuteFunction')
  @mock.patch('turbinia.client.task_manager.PSQTaskManager._backend_setup')
  @mock.patch('turbinia.state_manager.get_state_manager')
  def testClientFormatTaskStatusShortReport(self, _, __, ___):
    """Tests format_task_status() has valid output with short report."""
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


class TestTurbiniaStats(unittest.TestCase):
  """Test TurbiniaStats class."""

  def testTurbiniaStatsAddTask(self):
    """Tests TurbiniaStats.add_task() method."""
    test_task = {'run_time': None, 'last_update': None}
    stats = TurbiniaStats()
    stats.add_task(test_task)
    self.assertIn(test_task, stats.tasks)
    self.assertEqual(stats.count, 1)

  def testTurbiniaStatsCalculateStats(self):
    """Tests TurbiniaStats.calculateStats() method."""
    last_update = datetime.now()
    test_task1 = {'run_time': timedelta(minutes=3), 'last_update': last_update}
    test_task2 = {'run_time': timedelta(minutes=5), 'last_update': last_update}
    test_task3 = {'run_time': timedelta(minutes=1), 'last_update': last_update}

    stats = TurbiniaStats()
    stats.add_task(test_task1)
    stats.add_task(test_task2)
    stats.add_task(test_task3)
    stats.calculate_stats()

    self.assertEqual(stats.min, timedelta(minutes=1))
    self.assertEqual(stats.mean, timedelta(minutes=3))
    self.assertEqual(stats.max, timedelta(minutes=5))
    self.assertEqual(stats.count, 3)

  def testTurbiniaStatsCalculateStatsEmpty(self):
    """Tests that calculate_stats() works when no tasks are added."""
    stats = TurbiniaStats()
    stats.calculate_stats()
    self.assertEqual(stats.count, 0)
    self.assertEqual(stats.min, None)

  def testTurbiniaStatsFormatStats(self):
    """Tests TurbiniaStats.format_stats() returns valid output."""
    test_output = (
        'Test Task Results: Count: 1, Min: 0:03:00, Mean: 0:03:00, '
        'Max: 0:03:00')
    test_task1 = {
        'run_time': timedelta(minutes=3),
        'last_update': datetime.now()
    }
    stats = TurbiniaStats('Test Task Results')
    stats.add_task(test_task1)
    stats.calculate_stats()
    report = stats.format_stats()
    self.assertEqual(report, test_output)

  def testTurbiniaStatsFormatStatsCsv(self):
    """Tests TurbiniaStats.format_stats() returns valid CSV output."""
    test_output = ('Test Task Results, 1, 0:03:00, 0:03:00, 0:03:00')
    test_task1 = {
        'run_time': timedelta(minutes=3),
        'last_update': datetime.now()
    }
    stats = TurbiniaStats('Test Task Results')
    stats.add_task(test_task1)
    stats.calculate_stats()
    report = stats.format_stats_csv()
    self.assertEqual(report, test_output)


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
