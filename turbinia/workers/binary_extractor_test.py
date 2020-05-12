# -*- coding: utf-8 -*-
# Copyright 2016 Google Inc.
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
"""Tests for the Binary Extractor task."""

from __future__ import unicode_literals

import json
import mock
import os
import shutil
import tempfile
import unittest

from turbinia import TurbiniaException
from turbinia import config
from turbinia import evidence
from turbinia.evidence import BinaryExtraction
from turbinia.workers import binary_extractor
from turbinia.workers.workers_test import TestTurbiniaTaskBase
from turbinia.workers import TurbiniaTaskResult


class BinaryExtractorTaskTest(TestTurbiniaTaskBase):
  """Test for the Binary Extractor task."""

  def setUp(self):
    super(BinaryExtractorTaskTest, self).setUp(
        task_class=binary_extractor.BinaryExtractorTask,
        evidence_class=BinaryExtraction)
    self.task.output_dir = self.task.base_output_dir
    self.setResults(mock_run=False)
    self.extraction_dir = os.path.join(
        self.task.output_dir, 'extracted_binaries')

    os.mkdir(self.extraction_dir)
    hashes = [{
        "sha256":
            "553c231c45eda751710eabb479d08668f70464c14e60064190a7ec206f26b5f5",
        "paths": ["bin/bzcat"]
    }, {
        "sha256":
            "a106276270db8d3fe80a96dbb52f14f23f42a29bea12c68ac0f88d2e916471af",
        "paths": ["bin/echo", "home/echo"]
    }, {
        "sha256":
            "e21de6c5af94fa9d4e7f3295c8d25b93ab3d2d65982f5ef53c801669cc82dc47",
        "paths": ["sbin/visudo"]
    }, {
        "sha256":
            "129f4d0e36b38742fdfa8f1ea9a014818e4ce5c41d4a889435aecee58a1c7c39",
        "paths": ["sbin/tune2fs"]
    }]
    with open(os.path.join(self.extraction_dir, 'hashes.json'),
              'w') as json_file:
      json.dump(hashes, json_file)

  def tearDown(self):
    if os.path.exists(self.base_output_dir):
      shutil.rmtree(self.base_output_dir)

  def testBinaryExtractorRun(self):
    """Test BinaryExtractor task run."""
    self.task.execute = mock.MagicMock(return_value=0)
    result = self.task.run(self.evidence, self.result)

    self.task.execute.assert_called_once()
    self.assertIsInstance(result, TurbiniaTaskResult)

  def test_check_extraction(self):
    """Tests the check_extraction method."""

    test_files = {
        'bin': ['bzcat', 'echo'],
        'sbin': ['visudo', 'tune2fs'],
        'home': ['echo']
    }

    for subfolder, files in test_files.items():
      os.makedirs(os.path.join(self.extraction_dir, subfolder))
      for file in files:
        os.mknod(os.path.join(self.extraction_dir, subfolder, file))

    self.task.json_path = os.path.join(self.extraction_dir, 'hashes.json')
    self.task.binary_extraction_dir = self.extraction_dir

    binary_cnt, hash_cnt = self.task.check_extraction()

    self.assertEqual(binary_cnt, 5)
    self.assertEqual(hash_cnt, 4)

    # Test if hashes.json file is not generated.
    self.task.json_path = os.path.join(self.extraction_dir, 'non_exist')
    self.assertRaises(TurbiniaException, self.task.check_extraction)


if __name__ == '__main__':
  unittest.main()
