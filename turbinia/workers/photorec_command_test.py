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
"""Command construction tests for the Photorec worker."""

import os
import tempfile
import unittest
from types import SimpleNamespace
import mock

from turbinia.workers import photorec


class PhotorecCommandTest(unittest.TestCase):
  """Tests for PhotorecTask command construction."""

  def testPhotorecRunDoesNotUseShell(self):
    """Test photorec passes evidence paths as argv entries."""
    with tempfile.TemporaryDirectory() as output_dir:
      task = photorec.PhotorecTask(base_output_dir=output_dir)
      task.output_dir = output_dir
      evidence = SimpleNamespace(
          device_path=os.path.join(output_dir, 'disk;touch'), local_path=None)
      result = mock.MagicMock()
      task.execute = mock.MagicMock(return_value=(0, result))

      task.run(evidence, result)

      cmd = task.execute.call_args.args[0]
      kwargs = task.execute.call_args.kwargs
      self.assertIsInstance(cmd, list)
      self.assertIn(evidence.device_path, cmd)
      self.assertNotIn('shell', kwargs)


if __name__ == '__main__':
  unittest.main()
