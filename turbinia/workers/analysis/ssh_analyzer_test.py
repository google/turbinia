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
"""Task for Linux SSH analysis."""
import datetime
import os
import mock
import pandas as pd
import shutil
import unittest

from turbinia.evidence import RawDisk
from turbinia.workers import Priority
from turbinia.workers import TurbiniaTaskResult
from turbinia.workers.analysis import ssh_analyzer
from turbinia.workers.workers_test import TestTurbiniaTaskBase


class LinuxSSHAnalysisTaskTest(TestTurbiniaTaskBase):
  """Test for LinuxSSHAnalysisTask task."""

  def setUp(self):
    super(LinuxSSHAnalysisTaskTest, self).setUp(
        task_class=ssh_analyzer.LinuxSSHAnalysisTask, evidence_class=RawDisk)

    self.task.output_dir = self.task.base_output_dir
    self.output_file_path = os.path.join(
        self.task.output_dir, 'linux_ssh_analysis.md')
    self.remove_files.append(self.output_file_path)
    os.makedirs(os.path.join(self.task.output_dir, 'var', 'log'))
    self.setResults(mock_run=False)

  def tearDown(self):
    if os.path.exists(self.base_output_dir):
      shutil.rmtree(self.base_output_dir)

  def test_read_log_data(self):
    """Test reading log file on disk"""
    log_file = 'test_data/secure'
    if not os.path.exists(log_file):
      return

    with open(log_file, 'r', encoding='utf-8') as fh:
      data = fh.read()
    a = ssh_analyzer.LinuxSSHAnalysisTask()
    ssh_records = a.read_log_data(data, log_file, log_year=2022)
    self.assertEqual(27719, len(ssh_records))

  def test_parse_message_datetime(self):
    """Test parsing message datetime fields."""
    analyzer = ssh_analyzer.LinuxSSHAnalysisTask()

    # Testing Feb 8 13:30:45 Debian/CentOS format
    output = analyzer.parse_message_datetime(
        message_datetime=['Feb', '8', '13:30:45'], log_year=2023)
    expected_output = datetime.datetime(
        2023, 2, 8, 13, 30, 45, tzinfo=datetime.timezone.utc)
    self.assertEqual(expected_output, output)

    # Testing 2023-02-08T13:30:45.123456+11:00 OpenSUSE format
    output = analyzer.parse_message_datetime(
        message_datetime=['2023-02-08T13:30:45.123456+11:00'], log_year=0)
    expected_output = datetime.datetime(
        2023, 2, 8, 2, 30, 45, 123456, datetime.timezone.utc)
    self.assertEqual(expected_output, output)

    # Invalid datetime 2023-13-10 22:10:10
    output = analyzer.parse_message_datetime(
        message_datetime=['2023-13-10 22:10:10'], log_year=0)
    self.assertIsNone(output)

    # Invalid datetime random
    output = analyzer.parse_message_datetime(['random'], log_year=0)
    self.assertIsNone(output)

  @mock.patch('turbinia.lib.utils.extract_artifacts')
  @mock.patch(
      'turbinia.workers.analysis.ssh_analyzer.LinuxSSHAnalysisTask.brute_force_analysis'
  )
  @mock.patch(
      'turbinia.workers.analysis.ssh_analyzer.LinuxSSHAnalysisTask.read_logs')
  def test_run(
      self, mock_read_logs, mock_brute_force_analysis, mock_extract_artifacts):
    """Test LinuxSSHAnalysis task run."""
    self.task.setup(self.task)

    mock_extract_artifacts.return_value = ['secure', 'var/log/secure']

    df = pd.read_csv('test_data/secure.csv')
    mock_read_logs.return_value = df

    mock_brute_force_analysis.return_value = (
        Priority.MEDIUM, 'Brute force from 1 IP addresses',
        '## Brute Force Analysis\n\n### Brute Force from 192.168.40.6\n\n'
        '- Successful brute force from 192.168.40.6 as admin at 2022-10-08'
        ' 18:10:33 (duration=7)')

    result = self.task.run(self.evidence, self.result)

    self.assertIsInstance(result, TurbiniaTaskResult)
    self.assertEqual(
        result.report_data,
        '## Brute Force Analysis\n\n### Brute Force from 192.168.40.6\n\n'
        '- Successful brute force from 192.168.40.6 as admin at 2022-10-08'
        ' 18:10:33 (duration=7)')


if __name__ == '__main__':
  unittest.main()
