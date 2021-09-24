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
"""Tests for the Windows account analysis task."""

import os
import tempfile
import unittest

from turbinia import config
from turbinia.workers.analysis import windows_acct
from turbinia.workers.workers_test import TestTurbiniaTaskBase


class WindowsAccountAnalysisTaskTest(TestTurbiniaTaskBase):
  """Tests for WindowsAccountAnalysisTask Task."""

  TEST_DIR = None
  RAW_CREDS = [
      'testuser:1000:aad3b435b51404eeaad3b435b51404ee:9c7ae0f76b24aad74254914c2b191633:::',
      'testlocaluser:1004:aad3b435b51404eeaad3b435b51404ee:29f98734e7aa3df2454621ff3928d121:::',
      'badpassword:1005:aad3b435b51404eeaad3b435b51404ee:7a21990fcd3d759941e45c490f143d5f:::'
  ]
  EXPECTED_CREDENTIALS = {
      '29f98734e7aa3df2454621ff3928d121': 'testlocaluser',
      '7a21990fcd3d759941e45c490f143d5f': 'badpassword',
      '9c7ae0f76b24aad74254914c2b191633': 'testuser'
  }
  REGISTRY_REPORT = """#### **Registry analysis found 2 weak password(s)**
* **2 weak password(s) found:**
    * User 'badpassword' with password '12345'
    * User 'testlocaluser' with password 'google'"""

  def setUp(self):
    super(WindowsAccountAnalysisTaskTest,
          self).setUp(task_class=windows_acct.WindowsAccountAnalysisTask)
    self.setResults(mock_run=False)
    self.task.tmp_dir = tempfile.gettempdir()
    self.task.output_dir = self.task.base_output_dir
    self.remove_files.append(os.path.join(self.task.output_dir, 'impacket.log'))
    filedir = os.path.dirname(os.path.realpath(__file__))
    self.TEST_DIR = os.path.join(filedir, '..', '..', '..', 'test_data')

  def test_extract_windows_hashes(self):
    """Tests the extract_windows_hashes method."""
    config.LoadConfig()
    # pylint: disable=protected-access
    creds, credentials = self.task._extract_windows_hashes(
        self.result, self.TEST_DIR)
    self.assertDictEqual(credentials, self.EXPECTED_CREDENTIALS)
    self.assertCountEqual(creds, self.RAW_CREDS)

  def test_analyse_windows_creds(self):
    """Tests the analyse_windows_creds method."""
    config.LoadConfig()

    (report, priority, summary) = self.task._analyse_windows_creds(
        self.RAW_CREDS, self.EXPECTED_CREDENTIALS, timeout=30)
    self.assertEqual(report, self.REGISTRY_REPORT)
    self.assertEqual(priority, 10)
    self.assertEqual(summary, 'Registry analysis found 2 weak password(s)')


if __name__ == '__main__':
  unittest.main()
