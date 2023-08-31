# -*- coding: utf-8 -*-
# Copyright 2023 Google Inc.
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
"""Turbinia API server unit tests."""

import unittest

from turbinia.api.cli.turbinia_client.helpers import formatter

from textwrap import dedent


class TestTurbiniaAPIFormatter(unittest.TestCase):
  """ Test Turbinia API formatter."""

  WORKERS_API_RESPONSE = {
      'scheduled_tasks': 0,
      '58be0171c8f0': {
          'run_status': {
              '950ef885ec32490ea6ee080b1f646a53': {
                  'task_name': 'GrepTask',
                  'last_update': '2023-08-31T01:54:08.104314Z',
                  'status': 'Task GrepTask is running on 58be0171c8f0',
                  'run_time': '0:00:03.418060'
              },
              '8c7d486bdb7444cda564d308e0d13476': {
                  'task_name':
                      'FinalizeRequestTask',
                  'last_update':
                      '2023-08-31T01:54:18.108941Z',
                  'status':
                      'Task FinalizeRequestTask is running on 58be0171c8f0',
                  'run_time':
                      '0:00:01.807367'
              }
          },
          'queued_status': {},
          'other_status': {
              '89ab31b41d8b4c30b007b09139d23695': {
                  'task_name':
                      'PsortTask',
                  'last_update':
                      '2023-08-31T01:54:08.085727Z',
                  'status':
                      'Completed successfully in 0:00:01.940446 on 58be0171c8f0',
                  'run_time':
                      '0:00:01.940446'
              },
              '30ea24b95a6848faba91893605a9b143': {
                  'task_name': 'WordpressCredsAnalysisTask',
                  'last_update': '2023-08-31T01:54:08.072453Z',
                  'status': 'No weak passwords found',
                  'run_time': '0:00:04.259982'
              }
          }
      }
  }

  EXPECTED_WORKERS_OUTPUT = dedent(
      """\
      # Turbinia report for Worker activity within 7 days
      * 1 Worker(s) found.
      * 0 Task(s) unassigned or scheduled and pending Worker assignment.

      ## Worker Node: 58be0171c8f0
      ### Run Status
      * 950ef885ec32490ea6ee080b1f646a53 - GrepTask
          * Last Update: 2023-08-31T01:54:08.104314Z
          * Status: Task GrepTask is running on 58be0171c8f0
          * Run Time: 0:00:03.418060
      * 8c7d486bdb7444cda564d308e0d13476 - FinalizeRequestTask
          * Last Update: 2023-08-31T01:54:18.108941Z
          * Status: Task FinalizeRequestTask is running on 58be0171c8f0
          * Run Time: 0:00:01.807367

      ### Queued Status
      * No Tasks found.

      ### Other Status
      * 89ab31b41d8b4c30b007b09139d23695 - PsortTask
          * Last Update: 2023-08-31T01:54:08.085727Z
          * Status: Completed successfully in 0:00:01.940446 on 58be0171c8f0
          * Run Time: 0:00:01.940446
      * 30ea24b95a6848faba91893605a9b143 - WordpressCredsAnalysisTask
          * Last Update: 2023-08-31T01:54:08.072453Z
          * Status: No weak passwords found
          * Run Time: 0:00:04.259982
      """)

  STATISTICS_API_RESPONSE = {
      'all_tasks': {
          'count': 18,
          'min': '0:00:00',
          'mean': '0:00:04',
          'max': '0:00:13'
      },
      'successful_tasks': {
          'count': 18,
          'min': '0:00:00',
          'mean': '0:00:04',
          'max': '0:00:13'
      },
      'failed_tasks': {
          'count': 0,
          'min': 'None',
          'mean': 'None',
          'max': 'None'
      },
      'requests': {
          'count': 2,
          'min': '0:01:06',
          'mean': '0:01:07',
          'max': '0:01:07'
      },
      'tasks_per_type': {
          'FinalizeRequestTask': {
              'count': 2,
              'min': '0:00:00',
              'mean': '0:00:00',
              'max': '0:00:00'
          },
          'GrepTask': {
              'count': 2,
              'min': '0:00:00',
              'mean': '0:00:00',
              'max': '0:00:00'
          },
          'LinuxAccountAnalysisTask': {
              'count': 2,
              'min': '0:00:06',
              'mean': '0:00:07',
              'max': '0:00:07'
          },
          'PlasoHasherTask': {
              'count': 2,
              'min': '0:00:11',
              'mean': '0:00:12',
              'max': '0:00:12'
          },
          'PlasoParserTask': {
              'count': 2,
              'min': '0:00:11',
              'mean': '0:00:13',
              'max': '0:00:13'
          },
          'PostgresAccountAnalysisTask': {
              'count': 2,
              'min': '0:00:03',
              'mean': '0:00:04',
              'max': '0:00:04'
          },
          'PsortTask': {
              'count': 2,
              'min': '0:00:01',
              'mean': '0:00:01',
              'max': '0:00:01'
          },
          'WindowsAccountAnalysisTask': {
              'count': 2,
              'min': '0:00:04',
              'mean': '0:00:05',
              'max': '0:00:05'
          },
          'WordpressCredsAnalysisTask': {
              'count': 2,
              'min': '0:00:03',
              'mean': '0:00:04',
              'max': '0:00:04'
          }
      },
      'tasks_per_worker': {
          '58be0171c8f0': {
              'count': 18,
              'min': '0:00:00',
              'mean': '0:00:04',
              'max': '0:00:13'
          }
      },
      'tasks_per_user': {
          'root': {
              'count': 18,
              'min': '0:00:00',
              'mean': '0:00:04',
              'max': '0:00:13'
          }
      }
  }

  # pylint: disable=line-too-long
  EXPECTED_STATISTICS_RESPONSE = dedent(
      """
      # Execution time statistics for Turbinia:
      | TASK                             |   COUNT | MIN     | MEAN    | MAX     |
      |:---------------------------------|--------:|:--------|:--------|:--------|
      | All Tasks                        |      18 | 0:00:00 | 0:00:04 | 0:00:13 |
      | Successful Tasks                 |      18 | 0:00:00 | 0:00:04 | 0:00:13 |
      | Failed Tasks                     |       0 | None    | None    | None    |
      | Requests                         |       2 | 0:01:06 | 0:01:07 | 0:01:07 |
      | Type FinalizeRequestTask         |       2 | 0:00:00 | 0:00:00 | 0:00:00 |
      | Type GrepTask                    |       2 | 0:00:00 | 0:00:00 | 0:00:00 |
      | Type LinuxAccountAnalysisTask    |       2 | 0:00:06 | 0:00:07 | 0:00:07 |
      | Type PlasoHasherTask             |       2 | 0:00:11 | 0:00:12 | 0:00:12 |
      | Type PlasoParserTask             |       2 | 0:00:11 | 0:00:13 | 0:00:13 |
      | Type PostgresAccountAnalysisTask |       2 | 0:00:03 | 0:00:04 | 0:00:04 |
      | Type PsortTask                   |       2 | 0:00:01 | 0:00:01 | 0:00:01 |
      | Type WindowsAccountAnalysisTask  |       2 | 0:00:04 | 0:00:05 | 0:00:05 |
      | Type WordpressCredsAnalysisTask  |       2 | 0:00:03 | 0:00:04 | 0:00:04 |
      | Worker 58be0171c8f0              |      18 | 0:00:00 | 0:00:04 | 0:00:13 |
      | User root                        |      18 | 0:00:00 | 0:00:04 | 0:00:13 |
      """)

  def testWorkersMarkdownReport(self):
    """Test formatting workers Markdown report."""
    result = formatter.WorkersMarkdownReport(self.WORKERS_API_RESPONSE,
                                             7).generate_markdown()

    self.assertEqual(result, self.EXPECTED_WORKERS_OUTPUT)

  def testStatisticsMarkdownReport(self):
    """Test formatting statistics Markdown report."""
    result = formatter.StatsMarkdownReport(
        self.STATISTICS_API_RESPONSE).generate_markdown()

    self.assertEqual(result, self.EXPECTED_STATISTICS_RESPONSE.strip())
