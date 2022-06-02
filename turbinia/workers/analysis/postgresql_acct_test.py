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
import unittest

from turbinia import config
from turbinia.workers.analysis import postgresql_acct
from turbinia.workers.workers_test import TestTurbiniaTaskBase


class PostgresAcctAnalysisTaskTest(TestTurbiniaTaskBase):
  """Tests for PostgresAcctAnalysisTask Task."""

  TEST_DATA_DIR = None

  EXPECTED_CREDENTIALS = {'5f4dcc3b5aa765d61d8327deb882cf99': 'postgres'}

  POSTGRES_REPORT = """#### **PostgreSQL analysis found 1 weak password(s)**
* **1 weak password(s) found:**
    * User 'postgres' with password 'password'"""

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
    self.assertEqual(data_dirs, ['test_data'])

  def test_extract_creds(self):
    """Tests the _extract_creds method."""
    config.LoadConfig()
    task = postgresql_acct.PostgresAccountAnalysisTask()

    # pylint: disable=protected-access
    hashes = task._extract_creds(['/database'], self.evidence)
    self.assertDictEqual(hashes, self.EXPECTED_CREDENTIALS)

  def test_analyse_postgres_creds(self):
    """Tests the _analyse_postegres_creds method."""
    config.LoadConfig()
    task = postgresql_acct.PostgresAccountAnalysisTask()

    (report, priority, summary) = task._analyse_postgres_creds(
        self.EXPECTED_CREDENTIALS)
    self.assertEqual(report, self.POSTGRES_REPORT)
    self.assertEqual(priority, 10)
    self.assertEqual(summary, 'PostgreSQL analysis found 1 weak password(s)')