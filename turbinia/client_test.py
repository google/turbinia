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
import textwrap

import mock

from turbinia import config
from turbinia import client as TurbiniaClientProvider
from turbinia import TurbiniaException
from turbinia.client import TurbiniaStats

DATETIME_FORMAT = '%Y-%m-%dT%H:%M:%S.%fZ'

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

LONG_REPORT_REQUESTS = textwrap.dedent(
    """\
    # Turbinia report for Requests made within 7 days
    * 2 requests were made within this timeframe.

    ## Request ID: 0xFakeRequestId
    * Last Update: 2020-08-04T16:52:38.390390Z
    * Requester: myuser
    * Task Count: 2
    * Associated Evidence:
        * `/fake/path`
        * `/fake/path/2`
        * `/no/path/`
        * `/no/path/2`


    ## Request ID: 0xFakeRequestId2
    * Last Update: 2020-08-04T16:32:38.390390Z
    * Requester: myuser2
    * Task Count: 1
    * Associated Evidence:
        * `/fake/path/3`
        * `/no/path/3`
""")

LONG_REPORT_WORKERS = textwrap.dedent(
    """\
    # Turbinia report for Worker activity within 7 days
    * 2 Worker(s) found.
    * 0 Task(s) unassigned or scheduled and pending Worker assignment.

    ## Worker Node: fake_worker2
    ### Running Tasks
    * No Tasks found.

    ### Queued Tasks
    * No Tasks found.

    ### Finished Tasks
    * 0xfakeTaskId2 - TaskName2
        * Last Update: 2020-08-04T16:52:38.390390Z
        * Status: This second fake task executed
        * Run Time: 0:05:00


    ## Worker Node: fake_worker
    ### Running Tasks
    * No Tasks found.

    ### Queued Tasks
    * No Tasks found.

    ### Finished Tasks
    * 0xfakeTaskId - TaskName
        * Last Update: 2020-08-04T16:32:38.390390Z
        * Status: This fake task executed
        * Run Time: 0:01:00

    * 0xfakeTaskId3 - TaskName3
        * Last Update: 2020-08-04T16:32:38.390390Z
        * Status: Third Task Failed...
        * Run Time: 0:03:00


    ## Unassigned Worker Tasks
    * No Tasks found.
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
    TurbiniaClientProvider.RETRY_SLEEP = 0.001
    last_update = datetime.strptime(
        '2020-08-04T16:32:38.390390Z', DATETIME_FORMAT)
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
    client = TurbiniaClientProvider.get_turbinia_client()
    self.assertTrue(hasattr(client, 'task_manager'))

  @mock.patch('libcloudforensics.providers.gcp.internal.function.GoogleCloudFunction.ExecuteFunction')  # yapf: disable
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
    client = TurbiniaClientProvider.get_turbinia_client()
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
  @mock.patch('turbinia.client.task_manager.PSQTaskManager._backend_setup')
  @mock.patch('turbinia.state_manager.get_state_manager')
  def testTurbiniaClientGetTaskDataNoResults(self, _, __, mock_cloud_function):
    """Test for exception after empty results from cloud functions."""
    mock_cloud_function.return_value = {}
    client = TurbiniaClientProvider.get_turbinia_client()
    self.assertRaises(
        TurbiniaException, client.get_task_data, "inst", "proj", "reg")

  @mock.patch('libcloudforensics.providers.gcp.internal.function.GoogleCloudFunction.ExecuteFunction')  # yapf: disable
  @mock.patch('turbinia.client.task_manager.PSQTaskManager._backend_setup')
  @mock.patch('turbinia.state_manager.get_state_manager')
  def testTurbiniaClientGetTaskDataRetriableErrors(
      self, _, __, mock_cloud_function):
    """Test for retries after retriable errors returned from cloud functions."""
    mock_cloud_function.return_value = {'error': {'code': 503}}
    client = TurbiniaClientProvider.get_turbinia_client()
    self.assertRaises(
        TurbiniaException, client.get_task_data, "inst", "proj", "reg")
    self.assertEqual(
        mock_cloud_function.call_count, TurbiniaClientProvider.MAX_RETRIES)

  @mock.patch('libcloudforensics.providers.gcp.internal.function.GoogleCloudFunction.ExecuteFunction')  # yapf: disable
  @mock.patch('turbinia.client.task_manager.PSQTaskManager._backend_setup')
  @mock.patch('turbinia.state_manager.get_state_manager')
  def testTurbiniaClientGetTaskDataInvalidJson(
      self, _, __, mock_cloud_function):
    """Test for exception after bad json results from cloud functions."""
    mock_cloud_function.return_value = {'result': None}
    client = TurbiniaClientProvider.get_turbinia_client()
    self.assertRaises(
        TurbiniaException, client.get_task_data, "inst", "proj", "reg")

  @mock.patch('libcloudforensics.providers.gcp.internal.function.GoogleCloudFunction.ExecuteFunction')  # yapf: disable
  @mock.patch('turbinia.client.task_manager.PSQTaskManager._backend_setup')
  @mock.patch('turbinia.state_manager.get_state_manager')
  def testClientFormatTaskStatistics(self, _, __, ___):
    """Tests format_task_statistics() report output."""
    client = TurbiniaClientProvider.get_turbinia_client()
    client.get_task_data = mock.MagicMock()
    client.get_task_data.return_value = self.task_data
    stats_report = client.format_task_statistics('inst', 'proj', 'reg')
    self.maxDiff = None
    self.assertEqual(stats_report, STATISTICS_REPORT)

  @mock.patch('libcloudforensics.providers.gcp.internal.function.GoogleCloudFunction.ExecuteFunction')  # yapf: disable
  @mock.patch('turbinia.client.task_manager.PSQTaskManager._backend_setup')
  @mock.patch('turbinia.state_manager.get_state_manager')
  def testClientFormatTaskStatisticsCsv(self, _, __, ___):
    """Tests format_task_statistics() CSV report output."""
    client = TurbiniaClientProvider.get_turbinia_client()
    client.get_task_data = mock.MagicMock()
    client.get_task_data.return_value = self.task_data
    stats_report = client.format_task_statistics(
        'inst', 'proj', 'reg', csv=True)
    self.maxDiff = None
    self.assertEqual(stats_report, STATISTICS_REPORT_CSV)

  @mock.patch('libcloudforensics.providers.gcp.internal.function.GoogleCloudFunction.ExecuteFunction')  # yapf: disable
  @mock.patch('turbinia.client.task_manager.PSQTaskManager._backend_setup')
  @mock.patch('turbinia.state_manager.get_state_manager')
  def testClientGetTaskStatistics(self, _, __, ___):
    """Tests get_task_statistics() basic functionality."""
    client = TurbiniaClientProvider.get_turbinia_client()
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

  @mock.patch('libcloudforensics.providers.gcp.internal.function.GoogleCloudFunction.ExecuteFunction')  # yapf: disable
  @mock.patch('turbinia.client.task_manager.PSQTaskManager._backend_setup')
  @mock.patch('turbinia.state_manager.get_state_manager')
  def testClientFormatTaskStatus(self, _, __, ___):
    """Tests format_task_status() with empty report_priority."""
    client = TurbiniaClientProvider.get_turbinia_client()
    client.get_task_data = mock.MagicMock()
    self.task_data[0]['report_priority'] = None
    self.task_data[1]['report_priority'] = ''
    self.task_data[2].pop('report_priority')
    client.get_task_data.return_value = self.task_data
    result = client.format_task_status('inst', 'proj', 'reg')
    self.assertIn('Processed 3 Tasks', result.strip())

  @mock.patch('libcloudforensics.providers.gcp.internal.function.GoogleCloudFunction.ExecuteFunction')  # yapf: disable
  @mock.patch('turbinia.client.task_manager.PSQTaskManager._backend_setup')
  @mock.patch('turbinia.state_manager.get_state_manager')
  def testClientFormatTaskStatusShortReport(self, _, __, ___):
    """Tests format_task_status() has valid output with short report."""
    client = TurbiniaClientProvider.get_turbinia_client()
    client.get_task_data = mock.MagicMock()
    client.get_task_data.return_value = self.task_data
    result = client.format_task_status('inst', 'proj', 'reg')
    self.assertEqual(result.strip(), SHORT_REPORT.strip())

  @mock.patch('libcloudforensics.providers.gcp.internal.function.GoogleCloudFunction.ExecuteFunction')  # yapf: disable
  @mock.patch('turbinia.client.task_manager.PSQTaskManager._backend_setup')
  @mock.patch('turbinia.state_manager.get_state_manager')
  def testClientFormatTaskStatusFullReport(self, _, __, ___):
    """Tests format_task_status() has valid output with full report."""
    client = TurbiniaClientProvider.get_turbinia_client()
    client.get_task_data = mock.MagicMock()
    client.get_task_data.return_value = self.task_data
    result = client.format_task_status('inst', 'proj', 'reg', full_report=True)
    self.assertEqual(result.strip(), LONG_REPORT.strip())

  @mock.patch('libcloudforensics.providers.gcp.internal.function.GoogleCloudFunction.ExecuteFunction')  # yapf: disable
  @mock.patch('turbinia.client.task_manager.PSQTaskManager._backend_setup')
  @mock.patch('turbinia.state_manager.get_state_manager')
  def testClientFormatTaskStatusFiles(self, _, __, ___):
    """Tests format_task_status() has valid output with report and files."""
    client = TurbiniaClientProvider.get_turbinia_client()
    client.get_task_data = mock.MagicMock()
    client.get_task_data.return_value = self.task_data
    result = client.format_task_status(
        'inst', 'proj', 'reg', all_fields=True, full_report=True)
    self.assertEqual(result.strip(), LONG_REPORT_FILES.strip())

  @mock.patch('libcloudforensics.providers.gcp.internal.function.GoogleCloudFunction.ExecuteFunction')  # yapf: disable
  @mock.patch('turbinia.client.task_manager.PSQTaskManager._backend_setup')
  @mock.patch('turbinia.state_manager.get_state_manager')
  def testClientFormatRequestStatus(self, _, __, ___):
    """Tests format_request_status() with default days."""
    client = TurbiniaClientProvider.get_turbinia_client()
    client.get_task_data = mock.MagicMock()
    client.get_task_data.return_value = self.task_data
    result = client.format_request_status('inst', 'proj', 'reg')
    self.assertIn('Requests made within 7 days', result.strip())

  @mock.patch('libcloudforensics.providers.gcp.internal.function.GoogleCloudFunction.ExecuteFunction')  # yapf: disable
  @mock.patch('turbinia.client.task_manager.PSQTaskManager._backend_setup')
  @mock.patch('turbinia.state_manager.get_state_manager')
  def testClientFormatRequestStatusDays(self, _, __, ___):
    """Tests format_request_status() with custom days."""
    client = TurbiniaClientProvider.get_turbinia_client()
    client.get_task_data = mock.MagicMock()
    client.get_task_data.return_value = self.task_data
    result = client.format_request_status('inst', 'proj', 'reg', days=4)
    self.assertIn('Requests made within 4 days', result.strip())

  @mock.patch('libcloudforensics.providers.gcp.internal.function.GoogleCloudFunction.ExecuteFunction')  # yapf: disable
  @mock.patch('turbinia.client.task_manager.PSQTaskManager._backend_setup')
  @mock.patch('turbinia.state_manager.get_state_manager')
  def testClientFormatRequestStatusNoResults(self, _, __, ___):
    """Tests format_request_status() with no Task results."""
    client = TurbiniaClientProvider.get_turbinia_client()
    client.get_task_data = mock.MagicMock()
    client.get_task_data.return_value = ''
    result = client.format_request_status('inst', 'proj', 'reg', days=4)
    self.assertEqual('', result)

  @mock.patch('libcloudforensics.providers.gcp.internal.function.GoogleCloudFunction.ExecuteFunction')  # yapf: disable
  @mock.patch('turbinia.client.task_manager.PSQTaskManager._backend_setup')
  @mock.patch('turbinia.state_manager.get_state_manager')
  def testClientFormatRequestStatusFullReport(self, _, __, ___):
    """Tests format_request_status() has valid output with full report."""
    client = TurbiniaClientProvider.get_turbinia_client()
    client.get_task_data = mock.MagicMock()
    client.get_task_data.return_value = self.task_data
    result = client.format_request_status(
        'inst', 'proj', 'reg', all_fields=True)
    self.assertEqual(result.strip(), LONG_REPORT_REQUESTS.strip())

  @mock.patch('libcloudforensics.providers.gcp.internal.function.GoogleCloudFunction.ExecuteFunction')  # yapf: disable
  @mock.patch('turbinia.client.task_manager.PSQTaskManager._backend_setup')
  @mock.patch('turbinia.state_manager.get_state_manager')
  def testClientFormatWorkerStatus(self, _, __, ___):
    """Tests format_worker_status() with default days."""
    client = TurbiniaClientProvider.get_turbinia_client()
    client.get_task_data = mock.MagicMock()
    client.get_task_data.return_value = self.task_data
    result = client.format_worker_status('inst', 'proj', 'reg')
    self.assertIn(
        'Turbinia report for Worker activity within 7 days', result.strip())

  @mock.patch('libcloudforensics.providers.gcp.internal.function.GoogleCloudFunction.ExecuteFunction')  # yapf: disable
  @mock.patch('turbinia.client.task_manager.PSQTaskManager._backend_setup')
  @mock.patch('turbinia.state_manager.get_state_manager')
  def testClientFormatWorkerStatusDays(self, _, __, ___):
    """Tests format_worker_status() with custom days."""
    client = TurbiniaClientProvider.get_turbinia_client()
    client.get_task_data = mock.MagicMock()
    client.get_task_data.return_value = self.task_data
    result = client.format_worker_status('inst', 'proj', 'reg', days=4)
    self.assertIn(
        'Turbinia report for Worker activity within 4 days', result.strip())

  @mock.patch('libcloudforensics.providers.gcp.internal.function.GoogleCloudFunction.ExecuteFunction')  # yapf: disable
  @mock.patch('turbinia.client.task_manager.PSQTaskManager._backend_setup')
  @mock.patch('turbinia.state_manager.get_state_manager')
  def testClientFormatWorkerStatusNoResults(self, _, __, ___):
    """Tests format_worker_status() with no Task results."""
    client = TurbiniaClientProvider.get_turbinia_client()
    client.get_task_data = mock.MagicMock()
    client.get_task_data.return_value = ''
    result = client.format_worker_status('inst', 'proj', 'reg', days=4)
    self.assertEqual('', result)

  @mock.patch('libcloudforensics.providers.gcp.internal.function.GoogleCloudFunction.ExecuteFunction')  # yapf: disable
  @mock.patch('turbinia.client.task_manager.PSQTaskManager._backend_setup')
  @mock.patch('turbinia.state_manager.get_state_manager')
  def testClientFormatWorkStatusFullReport(self, _, __, ___):
    """Tests format_worker_status() has valid output with full report."""
    client = TurbiniaClientProvider.get_turbinia_client()
    client.get_task_data = mock.MagicMock()
    client.get_task_data.return_value = self.task_data
    result = client.format_worker_status('inst', 'proj', 'reg', all_fields=True)
    self.assertEqual(result.strip(), LONG_REPORT_WORKERS.strip())


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