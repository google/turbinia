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
"""Tests for the Wordpress access log analysis task."""

from __future__ import unicode_literals

import os
import unittest

from turbinia import config
from turbinia.workers.analysis import wordpress


class WordpressAccessLogAnalysisTaskTest(unittest.TestCase):
  """Tests for WordpressAccessLogAnalysis Task."""

  WORDPRESS_ACCESS_LOGS = None
  WORDPRESS_PWNED_REPORT = """Wordpress access logs found (install, theme_edit)
\t27/Jun/2018:19:29:54 +0000: Wordpress installation successful
\t27/Jun/2018:19:31:15 +0000: Wordpress theme editor edited file (header.php)
""" # pylint: disable=line-too-long

  def setUp(self):
    filedir = os.path.dirname(os.path.realpath(__file__))
    test_data = os.path.join(
        filedir, '..', '..', '..', 'test_data', 'wordpress_access_logs.txt')
    with open(test_data, 'r') as data:
      self.WORDPRESS_ACCESS_LOGS = data.read()

  def test_analyze_wp_access_logs(self):
    """Tests the analyze_wp_access_logs method."""
    config.LoadConfig()
    task = wordpress.WordpressAccessLogAnalysisTask()

    report = task.analyze_wp_access_logs(self.WORDPRESS_ACCESS_LOGS)
    self.assertEqual(report, self.WORDPRESS_PWNED_REPORT)


if __name__ == '__main__':
  unittest.main()
