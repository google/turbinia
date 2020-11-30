# -*- coding: utf-8 -*-
# Copyright 2016 Google Inc.
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
"""Tests for the Redis analysis task."""

from __future__ import unicode_literals

import unittest

from turbinia import config
from turbinia.workers import redis


class RedisAnalysisTaskTest(unittest.TestCase):
  """test for the Redis analysis task."""

  REDIS_BIND_EVERYWHERE = """# If port 0 is specified Redis will not listen
port 6379
bind 0.0.0.0 ::1
"""

  REDIS_BIND_EVERYWHERE_SUMMARY = """Insecure Redis configuration found."""

  REDIS_BIND_EVERYWHERE_REPORT = """#### **Insecure Redis configuration found.**
* Redis listening on every IP"""

  REDIS_BIND_NOWHERE = """# If port 0 is specified Redis will not listen
port 6379
"""
  REDIS_BIND_NOWHERE_REPORT = 'No issues found in Redis configuration'

  def test_analyse_redis_config(self):
    """Tests the analyze_redis_config method."""
    config.LoadConfig()
    task = redis.RedisAnalysisTask()

    (report, priority, summary) = task.analyse_redis_config(
        self.REDIS_BIND_EVERYWHERE)
    self.assertEqual(report, self.REDIS_BIND_EVERYWHERE_REPORT)
    self.assertEqual(priority, 20)
    self.assertEqual(summary, self.REDIS_BIND_EVERYWHERE_SUMMARY)

    report = task.analyse_redis_config(self.REDIS_BIND_NOWHERE)[0]
    self.assertEqual(report, self.REDIS_BIND_NOWHERE_REPORT)


if __name__ == '__main__':
  unittest.main()
