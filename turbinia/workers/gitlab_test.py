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
import shutil
import unittest

from turbinia import config
from turbinia.workers import gitlab
from turbinia.workers import TurbiniaTaskResult
from turbinia.workers.workers_test import TestTurbiniaTaskBase


class GitlabTaskTest(TestTurbiniaTaskBase):
  """Tests for the Gitlab Task."""

  SUMMARY = '#### **exif exploit detected in var/log/gitlab/workhorse.log**'
  TEST_DATA = None

  def setUp(self):
    super(GitlabTaskTest, self).setUp(task_class=gitlab.GitlabTask)
    self.setResults(mock_run=False)
    filedir = os.path.dirname(os.path.realpath(__file__))
    self.evidence.local_path = os.path.join(filedir, '..', '..', 'test_data')
    self.task.output_dir = self.task.base_output_dir

  def testGitlabRun(self):
    """Test Gitlab task run."""
    config.LoadConfig()
    result = self.task.run(self.evidence, self.result)

    self.assertIsInstance(result, TurbiniaTaskResult)

    self.assertEqual(result.report_priority, 20)
    self.assertEqual(result.report_data, self.SUMMARY)

  def tearDown(self):
    if os.path.exists(self.base_output_dir):
      shutil.rmtree(self.base_output_dir)


if __name__ == '__main__':
  unittest.main()
