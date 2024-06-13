# -*- coding: utf-8 -*-
# Copyright 2022 Google Inc.
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
import unittest

from turbinia.client import TurbiniaStats


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
