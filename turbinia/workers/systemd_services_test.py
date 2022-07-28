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
"""Tests for systemd services analysis task."""

from __future__ import unicode_literals

import unittest

from turbinia import config
from turbinia.workers import systemd_services


class SystemdServiceAnalysisTaskTest(unittest.TestCase):
  """Tests for systemd services analysis task."""

  suspicious_service = """[Unit]
Description=xsecurelock integration for gLinux

[Service]
Type=oneshot
ExecStart=/tmp/sbin/glinux-xsecurelock-integration

[Install]
WantedBy=multi-user.target"""

  legit_service = """[Unit]
Description=xsecurelock integration for gLinux

[Service]
Type=oneshot
ExecStart=/usr/sbin/glinux-xsecurelock-integration

[Install]
WantedBy=multi-user.target"""

  SERVICE_INSECURE_SUMMARY = "Suspicious service found."
  SERVICE_INSECURE_REPORT = """#### **Suspicious service found.**
* Binary was located in a suspicious location"""

  SERVICE_SECURE_SUMMARY = "No suspicious services found"

  def test_analyze_systemd_services(self):
    """Test services method"""
    config.LoadConfig()
    task = systemd_services.SystemdAnalysisTask()

    (report, priority, summary) = task.check_systemd_services(
        self.suspicious_service)
    self.assertEqual(report, self.SERVICE_INSECURE_REPORT)
    self.assertEqual(priority, 20)
    self.assertEqual(summary, self.SERVICE_INSECURE_SUMMARY)

    (report, priority, summary) = task.check_systemd_services(
        self.legit_service)
    self.assertEqual(summary, self.SERVICE_SECURE_SUMMARY)


if __name__ == '__main__':
  unittest.main()