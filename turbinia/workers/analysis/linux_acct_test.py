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
"""Tests for the Linux account analysis task."""

import os
import unittest

from turbinia import config
from turbinia.workers.analysis import linux_acct


class LinuxAccountAnalysisTaskTest(unittest.TestCase):
  """Tests for LinuxAccountAnalysisTask Task."""

  SHADOW_FILE = None
  EXPECTED_CREDENTIALS = {
      '*':
          'root',
      '$6$NS6w5Q6yjrlZiw7s$5jeyNS.bsw2p4nlbbMRI5H8oZnSbbwKs0Lsw94xCouqn/y/yQpKNA4vdPSr/wdA0isyUmq3BD..ZcirwOVNPF/':
          'testuser'
  }
  SHADOW_REPORT = """#### **Shadow file analysis found 1 weak password(s)**
* **1 weak password(s) found:**
    * User 'testuser' with password 'test'"""

  def setUp(self):
    super(LinuxAccountAnalysisTaskTest, self).setUp()
    filedir = os.path.dirname(os.path.realpath(__file__))
    test_data = os.path.join(filedir, '..', '..', '..', 'test_data', 'shadow')
    with open(test_data, 'r') as data:
      self.SHADOW_FILE = data.readlines()

  def test_extract_linux_credentials(self):
    """Tests the extract_linux_credentials method."""
    config.LoadConfig()
    task = linux_acct.LinuxAccountAnalysisTask()

    # pylint: disable=protected-access
    credentials = task._extract_linux_credentials(self.SHADOW_FILE)
    self.assertEqual(credentials, self.EXPECTED_CREDENTIALS)

  def test_analyse_shadow_file(self):
    """Tests the analyse_shadow_file method."""
    config.LoadConfig()
    task = linux_acct.LinuxAccountAnalysisTask()

    (report, priority, summary) = task.analyse_shadow_file(
        self.SHADOW_FILE, self.EXPECTED_CREDENTIALS)
    self.assertEqual(report, self.SHADOW_REPORT)
    self.assertEqual(priority, 10)
    self.assertEqual(summary, 'Shadow file analysis found 1 weak password(s)')


if __name__ == '__main__':
  unittest.main()
