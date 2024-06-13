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

from datetime import datetime
from datetime import timedelta
import importlib
import textwrap
import unittest
import mock

from turbinia import config
from turbinia import state_manager
from turbinia import client as TurbiniaClientProvider

DATETIME_FORMAT = '%Y-%m-%dT%H:%M:%S.%fZ'

SHORT_REPORT = textwrap.dedent(
    """\
    # Turbinia report 0xFakeRequestId
    * Processed 3 Tasks for user myuser

    # High Priority Tasks
    * TaskName2 (EvidenceName2): This second fake task executed

    # Successful Tasks
    * TaskName (EvidenceName): This fake task executed

    # Failed Tasks
    * TaskName3 (EvidenceName3): Third Task Failed...

    # Scheduled or Running Tasks
    * None
""")

LONG_REPORT = textwrap.dedent(
    """\
    # Turbinia report 0xFakeRequestId
    * Processed 3 Tasks for user myuser

    # High Priority Tasks
    ## TaskName2
    * **Evidence:** EvidenceName2
    * **Status:** This second fake task executed
    * Task Id: 0xfakeTaskId2
    * Executed on worker fake_worker2

    ### Task Reported Data
    #### Fake High priority Report
    * Fake Bullet

    # Successful Tasks
    * TaskName (EvidenceName): This fake task executed

    # Failed Tasks
    * TaskName3 (EvidenceName3): Third Task Failed...

    # Scheduled or Running Tasks
    * None
""")

LONG_REPORT_FILES = textwrap.dedent(
    """\
    # Turbinia report 0xFakeRequestId
    * Processed 3 Tasks for user myuser

    # High Priority Tasks
    ## TaskName2
    * **Evidence:** EvidenceName2
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
    * TaskName (EvidenceName): This fake task executed
        * `/no/path/`
        * `/fake/path`


    # Failed Tasks
    * TaskName3 (EvidenceName3): Third Task Failed...
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


class TestBaseTurbiniaClient(unittest.TestCase):
  """Test Turbinia client class."""

  def load_test_data(self):
    """Load test task data."""
    last_update = datetime.strptime(
        '2020-08-04T16:32:38.390390Z', DATETIME_FORMAT)
    self.task_data = [
        {
            'id': '0xfakeTaskId',
            'instance': 'MyTurbiniaInstance',
            'last_update': last_update,
            'name': 'TaskName',
            'evidence_name': 'EvidenceName',
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
            'evidence_name': 'EvidenceName2',
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
            'evidence_name': 'EvidenceName3',
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

  @mock.patch('turbinia.client.task_manager.CeleryTaskManager._backend_setup')
  def setUp(
      self,
      _,
  ):  #pylint: disable=arguments-differ
    """Initialize tests for Turbinia client."""
    config.LoadConfig()
    config.TASK_MANAGER = 'Celery'
    config.STATE_MANAGER = 'Redis'
    importlib.reload(state_manager)
    importlib.reload(TurbiniaClientProvider)
    self.client = TurbiniaClientProvider.get_turbinia_client()
    self.load_test_data()

  def testClientFormatTaskStatistics(self):
    """Tests format_task_statistics() report output."""
    client = self.client
    client.get_task_data = mock.MagicMock()
    client.get_task_data.return_value = self.task_data
    stats_report = client.format_task_statistics('inst', 'proj', 'reg')
    self.assertEqual(stats_report, STATISTICS_REPORT)

  def testClientFormatTaskStatisticsCsv(self):
    """Tests format_task_statistics() CSV report output."""
    client = self.client
    client.get_task_data = mock.MagicMock()
    client.get_task_data.return_value = self.task_data
    stats_report = client.format_task_statistics(
        'inst', 'proj', 'reg', csv=True)
    self.assertEqual(stats_report, STATISTICS_REPORT_CSV)

  def testClientGetTaskStatistics(self):
    """Tests get_task_statistics() basic functionality."""
    client = self.client
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

  def testClientFormatTaskStatus(self):
    """Tests format_task_status() with empty report_priority."""
    client = self.client
    client.get_task_data = mock.MagicMock()
    self.task_data[0]['report_priority'] = None
    self.task_data[1]['report_priority'] = ''
    self.task_data[2].pop('report_priority')
    client.get_task_data.return_value = self.task_data
    result = client.format_task_status('inst', 'proj', 'reg')
    self.assertIn('Processed 3 Tasks', result.strip())

  def testClientFormatTaskStatusShortReport(self):
    """Tests format_task_status() has valid output with short report."""
    client = self.client
    client.get_task_data = mock.MagicMock()
    client.get_task_data.return_value = self.task_data
    result = client.format_task_status('inst', 'proj', 'reg')
    self.assertEqual(result.strip(), SHORT_REPORT.strip())

  def testClientFormatTaskStatusFullReport(self):
    """Tests format_task_status() has valid output with full report."""
    client = self.client
    client.get_task_data = mock.MagicMock()
    client.get_task_data.return_value = self.task_data
    result = client.format_task_status('inst', 'proj', 'reg', full_report=True)
    self.assertEqual(result.strip(), LONG_REPORT.strip())

  def testClientFormatTaskStatusFiles(self):
    """Tests format_task_status() has valid output with report and files."""
    client = self.client
    client.get_task_data = mock.MagicMock()
    client.get_task_data.return_value = self.task_data
    result = client.format_task_status(
        'inst', 'proj', 'reg', all_fields=True, full_report=True)
    self.assertEqual(result.strip(), LONG_REPORT_FILES.strip())

  def testClientFormatRequestStatus(self):
    """Tests format_request_status() with default days."""
    client = self.client
    client.get_task_data = mock.MagicMock()
    client.get_task_data.return_value = self.task_data
    result = client.format_request_status('inst', 'proj', 'reg')
    self.assertIn('Requests made within 7 days', result.strip())

  def testClientFormatRequestStatusDays(self):
    """Tests format_request_status() with custom days."""
    client = self.client
    client.get_task_data = mock.MagicMock()
    client.get_task_data.return_value = self.task_data
    result = client.format_request_status('inst', 'proj', 'reg', days=4)
    self.assertIn('Requests made within 4 days', result.strip())

  def testClientFormatRequestStatusNoResults(self):
    """Tests format_request_status() with no Task results."""
    client = self.client
    client.get_task_data = mock.MagicMock()
    client.get_task_data.return_value = ''
    result = client.format_request_status('inst', 'proj', 'reg', days=4)
    self.assertEqual('', result)

  def testClientFormatRequestStatusFullReport(self):
    """Tests format_request_status() has valid output with full report."""
    client = self.client
    client.get_task_data = mock.MagicMock()
    client.get_task_data.return_value = self.task_data
    result = client.format_request_status(
        'inst', 'proj', 'reg', all_fields=True)
    self.assertEqual(result.strip(), LONG_REPORT_REQUESTS.strip())

  def testClientFormatWorkerStatus(self):
    """Tests format_worker_status() with default days."""
    client = self.client
    client.get_task_data = mock.MagicMock()
    client.get_task_data.return_value = self.task_data
    result = client.format_worker_status('inst', 'proj', 'reg')
    self.assertIn(
        'Turbinia report for Worker activity within 7 days', result.strip())

  def testClientFormatWorkerStatusDays(self):
    """Tests format_worker_status() with custom days."""
    client = self.client
    client.get_task_data = mock.MagicMock()
    client.get_task_data.return_value = self.task_data
    result = client.format_worker_status('inst', 'proj', 'reg', days=4)
    self.assertIn(
        'Turbinia report for Worker activity within 4 days', result.strip())

  def testClientFormatWorkerStatusNoResults(self):
    """Tests format_worker_status() with no Task results."""
    client = self.client
    client.get_task_data = mock.MagicMock()
    client.get_task_data.return_value = ''
    result = client.format_worker_status('inst', 'proj', 'reg', days=4)
    self.assertEqual('', result)

  def testClientFormatWorkStatusFullReport(self):
    """Tests format_worker_status() has valid output with full report."""
    client = self.client
    client.get_task_data = mock.MagicMock()
    client.get_task_data.return_value = self.task_data
    result = client.format_worker_status('inst', 'proj', 'reg', all_fields=True)
    self.assertEqual(result.strip(), LONG_REPORT_WORKERS.strip())


class TestTurbiniaClientRedis(TestBaseTurbiniaClient):
  """Run tests using a Redis client."""

  @mock.patch('turbinia.client.task_manager.CeleryTaskManager._backend_setup')
  def setUp(self, _):  #pylint: disable=arguments-differ
    """Initialize tests for Turbinia client."""
    config.LoadConfig()
    config.STATE_MANAGER = 'Redis'
    config.TASK_MANAGER = 'Celery'
    importlib.reload(state_manager)
    importlib.reload(TurbiniaClientProvider)
    self.client = TurbiniaClientProvider.get_turbinia_client()
    super().load_test_data()
