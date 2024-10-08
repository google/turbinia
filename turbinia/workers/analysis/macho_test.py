# -*- coding: utf-8 -*-
# Copyright 2024 Google Inc.
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
"""Tests for the Mach-O job."""

import logging
import os
import mock
import sys
import tempfile
import unittest

from turbinia import TurbiniaException
from turbinia.evidence import MachoExtraction
from turbinia.workers import TurbiniaTaskResult
from turbinia.workers.analysis import macho
from turbinia.workers.workers_test import TestTurbiniaTaskBase


class MachoAnalysisTaskTest(TestTurbiniaTaskBase):
  """Tests for MachoAnalysisTask Task."""

  def setUp(self):
    super(MachoAnalysisTaskTest, self).setUp(
        task_class=macho.MachoAnalysisTask, evidence_class=MachoExtraction)
    logging.basicConfig(stream=sys.stderr)
    self.setResults(mock_run=False)

    self.task.tmp_dir = tempfile.gettempdir()
    self.task.output_dir = self.task.base_output_dir

  def testRun(self):
    """Tests the run method."""
    filedir = os.path.dirname(os.path.realpath(__file__))
    self.evidence.compressed_directory = os.path.join(
        filedir, '..', '..', '..', 'test_data', 'macho-3.tgz'),
    self.task.run(self.evidence, self.result)
    logging.getLogger('turbinia').error(self.result)
    self.assertIsInstance(self.result, TurbiniaTaskResult)


if __name__ == '__main__':
  unittest.main()
