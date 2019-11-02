# -*- coding: utf-8 -*-
# Copyright 2019 Google Inc.
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
"""Tests for the Bulk Extractor job."""

from __future__ import unicode_literals
from shutil import rmtree
from io import StringIO

import os
import unittest
import textwrap
import mock

from turbinia.evidence import BulkExtractorOutput
from turbinia.workers import bulk_extractor
from turbinia.workers.workers_test import TestTurbiniaTaskBase
from turbinia.workers import TurbiniaTaskResult


class BulkExtractorTaskTest(TestTurbiniaTaskBase):
  """Tests for BulkExtractorTask."""

  def setUp(self):
    # pylint: disable=arguments-differ
    super(BulkExtractorTaskTest, self).setUp(
        task_class=bulk_extractor.BulkExtractorTask,
        evidence_class=BulkExtractorOutput)
    self.task.output_dir = self.task.base_output_dir
    self.setResults(mock_run=False)

  def tearDown(self):
    # Remove testing directory for this unit test.
    if os.path.exists(self.base_output_dir):
      rmtree(self.base_output_dir)

  def testBulkExtractorRun(self):
    """Test BulkExtractor task run."""
    self.task.execute = mock.MagicMock(return_value=0)
    result = self.task.run(self.evidence, self.result)

    # Ensure execute method is being called.
    self.task.execute.assert_called_once()
    # Ensure run method returns a TurbiniaTaskResult instance.
    self.assertIsInstance(result, TurbiniaTaskResult)

  @mock.patch('os.path')
  def test_generate_report(self, mock_path):
    """Tests Bulk Extractor report generation."""
    # pylint: disable=line-too-long
    empty_report_sample = textwrap.dedent(
        """\
        #### Bulk Extractor Results
        ##### Run Summary
        * Program: BULK_EXTRACTOR - 1.6.0-dev
        * Command Line: bulk_extractor /tmp/test-small.img -o /output/test-small.img
        * Start Time: 2019-09-27T16:34:48Z
        * Elapsed Time: N/A
        ##### There are no findings to report.""")

    summary_sample = "0 artifacts have been extracted."

    xml_sample = textwrap.dedent(
        """\
        <dfxml xmloutputversion="1.0">
        <creator version="1.0">
          <program>BULK_EXTRACTOR</program>
          <version>1.6.0-dev</version>
          <execution_environment>
            <command_line>bulk_extractor /tmp/test-small.img -o /output/test-small.img</command_line>
            <start_time>2019-09-27T16:34:48Z</start_time>
          </execution_environment>
        </creator>
        </dfxml>""")

    str_io = StringIO(xml_sample)
    mock_path.join.return_value = str_io
    mock_path.exists.return_value = True
    (report, summary) = self.task.generate_summary_report(str_io)
    self.assertEqual(empty_report_sample, report)
    self.assertEqual(summary_sample, summary)


if __name__ == '__main__':
  unittest.main()
