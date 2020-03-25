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
"""Tests for the Photorec job."""

from __future__ import unicode_literals

import os
import unittest
import textwrap
import mock

from turbinia.evidence import PhotorecOutput
from turbinia.workers import photorec
from turbinia.workers.workers_test import TestTurbiniaTaskBase
from turbinia.workers import TurbiniaTaskResult


class PhotorecTaskTest(TestTurbiniaTaskBase):
  """Tests for PhotorecTask."""

  def setUp(self):
    # pylint: disable=arguments-differ
    super(PhotorecTaskTest, self).setUp(
        task_class=photorec.PhotorecTask, evidence_class=PhotorecOutput)
    self.setResults(mock_run=False)
    self.task.output_dir = self.task.base_output_dir

  def testPhotorecRun(self):
    """Test photorec task run."""
    self.task.execute = mock.MagicMock(return_value=0)
    result = self.task.run(self.evidence, self.result)

    # Ensure execute method is being called.
    self.task.execute.assert_called_once()
    # Ensure run method returns a TurbiniaTaskResult instance.
    self.assertIsInstance(result, TurbiniaTaskResult)


if __name__ == '__main__':
  unittest.main()
