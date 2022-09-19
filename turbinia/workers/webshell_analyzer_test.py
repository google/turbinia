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
"""Tests for the Webshell Analyzer task."""

from shutil import rmtree
import unittest
import os
from turbinia.workers import webshell_analyzer
from turbinia.workers.workers_test import TestTurbiniaTaskBase


class WebshellAnalyzerTaskTest(TestTurbiniaTaskBase):
  """test for WebShellAnalysisTask Task"""

  def setUp(self):
    super(WebshellAnalyzerTaskTest,
          self).setUp(task_class=webshell_analyzer.WebshellAnalyzerTask)
    self.setResults(mock_run=False)
    filedir = os.path.dirname(os.path.realpath(__file__))
    print(filedir)
    self.evidence.local_path = os.path.join(filedir, '..', '..', 'test_data')
    self.task.output_dir = self.task.base_output_dir

  def tearDown(self):
    if os.path.exists(self.task.output_dir):
      rmtree(self.task.output_dir)

  def test_webanalyzer(self):
    """test"""

    WEBSHELL_SUMMARY = 'Webshell Analyzer found 1 webshell(s)'

    (report, priority, summary) = self.task.find_webshells(
        self.result, self.evidence)
    self.assertEqual(priority, 20)
    self.assertEqual(summary, WEBSHELL_SUMMARY)
    self.assertIn('filePath', report)


if __name__ == '__main__':
  unittest.main()
