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

import unittest
import mock
import os
import json
from turbinia import evidence
from turbinia.workers import webshell_analyzer
from turbinia.workers.workers_test import TestTurbiniaTaskBase


class WebshellAnalyzerTaskTest(TestTurbiniaTaskBase):
  """test for WebShellAnalysisTask Task"""

  WEBSHELL_SUMMARY = 'Webshell Analyzer found 1 webshell(s)'

  def setUp(self):
    super(WebshellAnalyzerTaskTest,
          self).setUp(task=webshell_analyzer.WebshellAnalyzerTask)

    self.task_output_dir = self.task.base_output_dir
    print(self.task.output_dir)
    self.setResults(mock_run=False)

  @mock.patch('os.path')
  @mock.patch('json.loads')
  def test_webanalyzer(self, mock_json_loads, mock_path):
    """test"""
    WEBSHEL_FOUND_REPORT = '{"filePath":"/tmp/turbinia-mounts/turbinia3n99_lpb/var/apache/devilzShell.php","size":48668,\
      "hashes":{"md5":"02e8597a4ddade7b69f6fa546ebfe170","sha1":"85a6815fda2c9661e3618b14543eb578e7c71020",\
        "sha256":"cc3b076aa6d2377ae0a28de2fa5009c5898e3343b094b2d632fadc31452df502"},\
          "timestamps":{"created":"2022-09-06 21:20:06","modified":"2022-09-06 20:48:51","accessed":"2022-09-06 21:20:31"},\
            "matches":{"CMD":1,"cmD":1,"cmd":25},"decodes":{"Generic_Base64Decode":13,"Generic_Multiline_Base64Decode":42},\
              "attributes":{"Generic_Embedding_Code_C":{"bind(":2,"daemon(1,0)":2,"include \u003csys/socket[.]h\u003e":4,\
                "listen(":2,"socket(AF_INET,SOCK_STREAM":2},\
                  "Generic_Windows_Commands":{"CMD":1,"cmD":1,"cmd":25},\
                    "PHP_Banned_Function":{"exec(":2,"link(":12,"listen(":2,\
                      "passthru(":1,"realpath(":17,"set_time_limit(":1},\
                        "PHP_Defense_Evasion":{"preg_replace(":1},\
                          "PHP_Disk_Operations":{"\trename(":1,"fopen(":2},"PHP_Reconnaissance":{"posix_getgrgid(":1,"posix_getpwuid(":1}}}'

    mock_json_loads.return_value = WEBSHEL_FOUND_REPORT
    mock_path.exists.return_vaule = True
    evidence.mount_path = '/tmp'

    (report, priority) = self.task.find_webshells(
        self.evidence, WEBSHEL_FOUND_REPORT)

    self.assertEqual(priority, 20)
    self.assertEqual(self.WEBSHELL_FOUND_REPORT, report)


if __name__ == '__main__':
  unittest.main()
