# -*- coding: utf-8 -*-
# Copyright 2024 Google Inc.
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
"""Tests for the Chrome Credentials analysis task."""

import os
import unittest

from turbinia import config
from turbinia.workers.analysis import chromecreds


class ChromeCredsAnalysisTaskTest(unittest.TestCase):
  """Tests for ChromeCredentialsAnslysisTask."""

  EXPECTED_CREDENTIALS = {'http://test.com': ['testuser']}
  TWO_CREDENTIALS = {
      'http://test.com': ['testuser'],
      'http://example.com': ['exampleuser', 'admin']
  }
  TEST_SQL = None
  CREDS_REPORT = """#### **2 saved credentials found in Chrome Login Data**
* **Credentials:**
    * Site 'http://test.com' with users '['testuser']'
    * Site 'http://example.com' with users '['exampleuser', 'admin']'"""

  def setUp(self):
    super(ChromeCredsAnalysisTaskTest, self).setUp()
    filedir = os.path.dirname(os.path.realpath(__file__))
    self.TEST_SQL = os.path.join(
        filedir, '..', '..', '..', 'test_data', 'test_login_data.sqlite')

  def test_extract_chrome_creds(self):
    """Tests the extract_chrome_creds method."""
    config.LoadConfig()
    task = chromecreds.ChromeCredsAnalysisTask()

    # pylint: disable=protected-access
    credentials = task._extract_chrome_creds(self.TEST_SQL)
    self.assertEqual(credentials, self.EXPECTED_CREDENTIALS)

  def test_summarise_creds(self):
    """Tests the summarise_creds method."""
    config.LoadConfig()
    task = chromecreds.ChromeCredsAnalysisTask()

    (report, priority, summary) = task.summarise_creds(self.TWO_CREDENTIALS)
    self.assertEqual(report, self.CREDS_REPORT)
    self.assertEqual(priority, 50)
    self.assertEqual(summary, '2 saved credentials found in Chrome Login Data')
