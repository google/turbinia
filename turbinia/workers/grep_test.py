# -*- coding: utf-8 -*-
# Copyright 2026 Google Inc.
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
"""Tests for the Grep worker."""

import os
import tempfile
import unittest
from types import SimpleNamespace
import mock

from turbinia.workers import grep


class GrepTaskTest(unittest.TestCase):
  """Tests for GrepTask."""

  def testGrepRunDoesNotUseShell(self):
    """Test grep passes paths as argv entries instead of shell text."""
    with tempfile.TemporaryDirectory() as output_dir:
      task = grep.GrepTask(base_output_dir=output_dir)
      task.output_dir = output_dir
      task.task_config = {'filter_patterns': ['needle']}
      evidence = SimpleNamespace(
          local_path=os.path.join(output_dir, 'input;touch'), name='input')
      result = mock.MagicMock()
      task.execute = mock.MagicMock(return_value=(0, result))

      task.run(evidence, result)

      cmd = task.execute.call_args.args[0]
      kwargs = task.execute.call_args.kwargs
      self.assertIsInstance(cmd, list)
      self.assertIn(evidence.local_path, cmd)
      self.assertNotIn('shell', kwargs)
      self.assertTrue(kwargs['stdout_file'].endswith('.filtered'))


if __name__ == '__main__':
  unittest.main()
