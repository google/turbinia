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
"""Tests for the Plaso worker task."""

import logging
import os
import sys

from turbinia.workers import plaso
from turbinia.workers.workers_test import TestTurbiniaTaskBase


class PlasoTaskTest(TestTurbiniaTaskBase):
  """Tests for PlasoTask."""

  _BASE_COMMAND = "log2timeline"
  _YARA_RULE = """
rule rulename {
  strings:
    $one = "one"
  condition:
    all of them
}
  """

  def setUp(self):
    super(PlasoTaskTest, self).setUp()
    logging.basicConfig(stream=sys.stderr)
    self.setResults(mock_run=True)
    self.plaso_task.result = self.result
    self.plaso_task.job_name = 'PlasoJob'

  def test_build_command_no_cli_arg(self):
    command = self.plaso_task.build_plaso_command(self._BASE_COMMAND, {})
    self.assertEqual(command, [self._BASE_COMMAND])

  def test_build_command_bad_cli_arg(self):
    command = self.plaso_task.build_plaso_command(
        self._BASE_COMMAND, {'badArg': 'test'})
    self.assertEqual(command, [self._BASE_COMMAND])

  def test_build_command_good_cli_arg(self):
    command = self.plaso_task.build_plaso_command(
        self._BASE_COMMAND, {'status_view': 'none'})
    self.assertEqual(command, [self._BASE_COMMAND, "--status_view", "none"])
    return

  def test_build_command_good_yara(self):
    if not os.path.isfile(os.path.expanduser('/opt/fraken/fraken')):
      logging.getLogger('turbinia').error('Fraken not installed')
      return
    command = self.plaso_task.build_plaso_command(
        self._BASE_COMMAND, {'yara_rules': self._YARA_RULE})
    self.assertIn("--yara_rules", command)

  def test_build_command_bad_yara(self):
    if not os.path.isfile(os.path.expanduser('/opt/fraken/fraken')):
      logging.getLogger('turbinia').error('Fraken not installed')
      return
    command = self.plaso_task.build_plaso_command(
        self._BASE_COMMAND, {'yara_rules': self._YARA_RULE + self._YARA_RULE})
    self.assertNotIn("--yara_rules", command)