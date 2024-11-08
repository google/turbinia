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
  TEST_SQL = None

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
