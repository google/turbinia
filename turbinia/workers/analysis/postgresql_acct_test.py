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
"""Tests for the PostgreSQL account analysis task."""

import os
import mock
import unittest

from turbinia import config
from turbinia.workers.analysis import postgresql_acct
from turbinia.workers.workers_test import TestTurbiniaTaskBase


class PostgresAcctAnalysisTaskTest(TestTurbiniaTaskBase):
  """Tests for PostgresAcctAnalysisTask Task."""

  TEST_DATA_DIR = None

  EXPECTED_MD5_CREDENTIALS = {'5f4dcc3b5aa765d61d8327deb882cf99': 'postgres'}
  EXPECTED_SCRAM_CREDENTIALS = {
      'SCRAM-SHA-256$4096:APJq+0/Y/X3zrBg2AWyKkQ==$Qe9RKFYZJPhd14z1Iqs1agjzxGlBPexsTEHIhos6wrM=:Z9MGrSmyQvM4owINbGzK8HxhFzVWDcSYYD+s44sQvV8=':
          'postgres'
  }

  POSTGRES_REPORT = """#### **PostgreSQL analysis found 1 weak password(s)**
* **1 weak password(s) found:**
    * User 'postgres' with password 'postgres'"""

  def setUp(self):
    super(PostgresAcctAnalysisTaskTest, self).setUp()
    self.setResults(mock_run=False)
    filedir = os.path.dirname(os.path.realpath(__file__))
    self.TEST_DATA_DIR = os.path.join(filedir, '..', '..', '..', 'test_data')
    self.evidence.local_path = self.TEST_DATA_DIR

  def test_extract_data_dir(self):
    """Tests the _extract_data_dir method."""
    config.LoadConfig()
    task = postgresql_acct.PostgresAccountAnalysisTask()

    # pylint: disable=protected-access
    data_dirs = task._extract_data_dir(self.TEST_DATA_DIR, self.result)
    self.assertEqual(len(data_dirs), 1)
    self.assertTrue(data_dirs[0].endswith('test_data'))

  def test_extract_md5_creds(self):
    """Tests the _extract_creds method."""
    config.LoadConfig()
    task = postgresql_acct.PostgresAccountAnalysisTask()

    # pylint: disable=protected-access
    hashes, _ = task._extract_creds(['/database'], self.evidence)
    self.assertDictEqual(hashes, self.EXPECTED_MD5_CREDENTIALS)

  def test_extract_scram_creds(self):
    """Tests the _extract_creds method."""
    config.LoadConfig()
    task = postgresql_acct.PostgresAccountAnalysisTask()

    # pylint: disable=protected-access
    _, hashes = task._extract_creds(['/scram_database'], self.evidence)
    self.assertDictEqual(hashes, self.EXPECTED_SCRAM_CREDENTIALS)

  @mock.patch(
      'turbinia.workers.analysis.postgresql_acct.bruteforce_password_hashes')
  def test_analyse_md5_postgres_creds(self, bruteforce_mock):
    """Tests the _analyse_postgres_creds method."""
    config.LoadConfig()
    task = postgresql_acct.PostgresAccountAnalysisTask()

    bruteforce_mock.side_effect = [
        [(list(self.EXPECTED_MD5_CREDENTIALS.keys())[0], 'postgres')], []
    ]

    (report, priority, summary) = task._analyse_postgres_creds(
        self.EXPECTED_MD5_CREDENTIALS, {})
    self.assertEqual(report, self.POSTGRES_REPORT)
    self.assertEqual(priority, 10)
    self.assertEqual(summary, 'PostgreSQL analysis found 1 weak password(s)')

  @mock.patch(
      'turbinia.workers.analysis.postgresql_acct.bruteforce_password_hashes')
  def test_analyse_scram_postgres_creds(self, bruteforce_mock):
    """Tests the _analyse_postgres_creds method."""
    config.LoadConfig()
    task = postgresql_acct.PostgresAccountAnalysisTask()

    bruteforce_mock.side_effect = [
        [], [(list(self.EXPECTED_SCRAM_CREDENTIALS.keys())[0], 'postgres')]
    ]

    (report, priority, summary) = task._analyse_postgres_creds(
        {}, self.EXPECTED_SCRAM_CREDENTIALS)
    self.assertEqual(report, self.POSTGRES_REPORT)
    self.assertEqual(priority, 10)
    self.assertEqual(summary, 'PostgreSQL analysis found 1 weak password(s)')
