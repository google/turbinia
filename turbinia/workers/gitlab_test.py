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
"""Tests for the Gitlab task."""

import os
import unittest

from turbinia import config
from turbinia.workers import gitlab
from turbinia.workers.workers_test import TestTurbiniaTaskBase


class GitlabTaskTest(TestTurbiniaTaskBase):
  """Tests for the Gitlab Task."""

  SUMMARY = 'exif exploit detected in workhorse.log'
  TEST_DATA = None

  def setUp(self):
    super(GitlabTaskTest, self).setUp(task_class=gitlab.GitlabTask)
    self.setResults(mock_run=True)
    filedir = os.path.dirname(os.path.realpath(__file__))
    self.TEST_DATA = os.path.join(filedir, '..', '..', 'test_data')

  def testGitlab(self):
    """Tests the extract_linux_credentials method."""
    config.LoadConfig()
    (report, priority, summary) = self.task._is_exif_in_logs(
        self.result, self.TEST_DATA, 'workhorse.log')
    self.assertEqual(priority, 20)
    self.assertEqual(summary, self.SUMMARY)


if __name__ == '__main__':
  unittest.main()
