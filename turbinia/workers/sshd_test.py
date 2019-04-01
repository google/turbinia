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
"""Tests for the SSHD analysis task."""

from __future__ import unicode_literals

import unittest

from turbinia import config
from turbinia.workers import sshd


class SSHDAnalysisTaskTest(unittest.TestCase):
  """test for the SSHD analysis task."""

  SSH_INSECURE_EVERYTHING = """PermitRootLogin Yes
PasswordAuthentication yes
PermitEmptyPasswords Yes
  """

  SSH_INSECURE_EVERYTHING_REPORT = """#### **Insecure SSH configuration found.**
* Root login enabled.
* Password authentication enabled.
* Empty passwords permitted."""

  SSH_INSECURE_EVERYTHING_SUMMARY = 'Insecure SSH configuration found.'

  SSH_SECURE_EVERYTHING = """PermitRootLogin No
PasswordAuthentication no
PermitEmptyPasswords no"""

  SSH_SECURE_EVERYTHING_REPORT = 'No issues found in SSH configuration'

  def test_analyse_sshd_config(self):
    """Tests the analyze_sshd_config method."""
    config.LoadConfig()
    task = sshd.SSHDAnalysisTask()

    (report, priority, summary) = task.analyse_sshd_config(
        self.SSH_INSECURE_EVERYTHING)
    self.assertEqual(report, self.SSH_INSECURE_EVERYTHING_REPORT)
    self.assertEqual(priority, 20)
    self.assertEqual(summary, self.SSH_INSECURE_EVERYTHING_SUMMARY)

    report = task.analyse_sshd_config(self.SSH_SECURE_EVERYTHING)[0]
    self.assertEqual(report, self.SSH_SECURE_EVERYTHING_REPORT)


if __name__ == '__main__':
  unittest.main()
