# -*- coding: utf-8 -*-
# Copyright 2021 Google Inc.
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
"""Tests for the Wordpress creds analysis task."""

import os
import unittest

from turbinia import config
from turbinia.workers.analysis import wordpress_creds
from turbinia.workers.workers_test import TestTurbiniaTaskBase


class WordpressCredsAnalysisTaskTest(TestTurbiniaTaskBase):
  """Tests for WordpressCredsAnalysisTask Task."""

  RAW_CREDS = [
      'administrator:$P$B2T1F/l3qBG7Oa5NzfvGtxwC2IkZJ4.',
      'fry_admin:$P$BtjlVfsamJoXPr7uMyJ7vD03DZj6w1/',
      'fry_not_admin:$P$B64.ME6zGFIKH46TXnKn79oHmOdp6Y0'
  ]

  EXPECTED_CREDENTIALS = {
      '$P$B2T1F/l3qBG7Oa5NzfvGtxwC2IkZJ4.': 'administrator',
      '$P$BtjlVfsamJoXPr7uMyJ7vD03DZj6w1/': 'fry_admin',
      '$P$B64.ME6zGFIKH46TXnKn79oHmOdp6Y0': 'fry_not_admin'
  }

  WORDPRESS_REPORT = """#### **Wordpress analysis found 3 weak password(s)**
* **3 weak password(s) found:**
    * User 'administrator' with password 'password'
    * User 'fry_not_admin' with password 'qwerty'
    * User 'fry_admin' with password 'abc123'"""

  TEST_DATA_DIR = None

  def setUp(self):
    super(WordpressCredsAnalysisTaskTest, self).setUp()
    filedir = os.path.dirname(os.path.realpath(__file__))
    self.TEST_DATA_DIR = os.path.join(filedir, '..', '..', '..', 'test_data')

  def test_extract_wordpress_hashes(self):
    """Tests the _extract_wordpress_hashes method."""
    config.LoadConfig()
    task = wordpress_creds.WordpressCredsAnalysisTask()

    # pylint: disable=protected-access
    creds, hashnames = task._extract_wordpress_hashes(self.TEST_DATA_DIR)
    self.assertCountEqual(creds, self.RAW_CREDS)
    self.assertDictEqual(hashnames, self.EXPECTED_CREDENTIALS)

  def test_analyse_wordpress_creds(self):
    """Tests the _analyse_wordpress_creds method."""
    config.LoadConfig()
    task = wordpress_creds.WordpressCredsAnalysisTask()

    (report, priority, summary) = task._analyse_wordpress_creds(
        self.RAW_CREDS, self.EXPECTED_CREDENTIALS)
    self.assertEqual(report, self.WORDPRESS_REPORT)
    self.assertEqual(priority, 10)
    self.assertEqual(summary, 'Wordpress analysis found 3 weak password(s)')


if __name__ == '__main__':
  unittest.main()
