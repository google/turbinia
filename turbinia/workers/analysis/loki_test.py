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
"""Tests for the Loki analysis task."""

import logging
import os
import sys
import tempfile
import unittest

from turbinia.workers.analysis import loki
from turbinia.workers.workers_test import TestTurbiniaTaskBase


class LokiAnalysisTaskTest(TestTurbiniaTaskBase):
  """Tests for LokiAnalysisTask Task."""

  LOKI_SUMMARY = 'Loki analysis found 1 alert(s)'

  TEST_DATA_DIR = None

  def setUp(self):
    super(LokiAnalysisTaskTest, self).setUp(task_class=loki.LokiAnalysisTask)
    logging.basicConfig(stream=sys.stderr)
    self.setResults(mock_run=True)
    filedir = os.path.dirname(os.path.realpath(__file__))
    self.evidence.local_path = os.path.join(
        filedir, '..', '..', '..', 'test_data')
    self.task.tmp_dir = tempfile.gettempdir()
    self.task.output_dir = self.task.base_output_dir
    self.remove_files.extend([
        os.path.join(self.task.output_dir, 'loki.log'),
        os.path.join(self.task.output_dir, 'loki_stdout.log'),
        os.path.join(self.task.output_dir, 'loki_stderr.log')
    ])

  def test_loki(self):
    """Tests the runLoki method."""
    # Check if installed
    if not os.path.isfile(os.path.expanduser('/opt/loki/loki.py')):
      logging.getLogger('turbinia').error('Loki not installed')
      return

    (report, priority, summary) = self.task.runLoki(self.result, self.evidence)
    self.assertEqual(priority, 20)
    self.assertEqual(summary, self.LOKI_SUMMARY)
    self.assertIn('Mimikatz', report)


if __name__ == '__main__':
  unittest.main()
