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
"""Tests for the Yara analysis task."""

import logging
import os
import mock
import sys
import tempfile
import unittest

from turbinia import TurbiniaException
from turbinia.workers.analysis import yara
from turbinia.workers.workers_test import TestTurbiniaTaskBase


class YaraAnalysisTaskTest(TestTurbiniaTaskBase):
  """Tests for YaraAnalysisTask Task."""

  YARA_SUMMARY = 'Yara analysis found 4 alert(s)'

  TEST_DATA_DIR = None

  def setUp(self):
    super(YaraAnalysisTaskTest, self).setUp(task_class=yara.YaraAnalysisTask)
    logging.basicConfig(stream=sys.stderr)
    self.setResults(mock_run=True)
    filedir = os.path.dirname(os.path.realpath(__file__))
    self.evidence.local_path = os.path.join(
        filedir, '..', '..', '..', 'test_data')
    self.task.tmp_dir = tempfile.gettempdir()
    self.task.output_dir = self.task.base_output_dir
    self.remove_files.extend([
        os.path.join(
            self.task.output_dir, f'{self.task.id:s}_fraken_stdout.log'),
        os.path.join(
            self.task.output_dir, f'{self.task.id:s}_fraken_stderr.log'),
    ])

  def test_yara(self):
    """Tests the runFraken method."""
    # Check if installed
    if not os.path.isfile(os.path.expanduser('/opt/fraken/fraken')):
      logging.getLogger('turbinia').error('Fraken not installed')
      return

    (report, priority, summary) = self.task.runFraken(
        self.result, self.evidence)
    self.assertEqual(priority, 20)
    self.assertEqual(summary, self.YARA_SUMMARY)
    self.assertIn('Mimikatz', report)
    self.assertIn('Hadoop', report)
    self.assertIn('Gitlab', report)

  def test_yara_no_stderr(self):
    """Tests the runFraken method errors with no stderr output."""
    self.task.execute = mock.MagicMock()
    # Mocking execute means the stderr file will never get created.
    self.task.execute.return_value = (1, mock.MagicMock())

    self.assertRaisesRegex(
        TurbiniaException, '.*Unknown \(no stderr\).*', self.task.runFraken,
        self.result, self.evidence)


if __name__ == '__main__':
  unittest.main()
