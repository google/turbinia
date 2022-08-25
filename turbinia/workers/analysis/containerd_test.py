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
"""Tests for ContainerdEnumerationTask."""

from __future__ import unicode_literals

import os
import unittest

from turbinia.evidence import ContainerdContainer
from turbinia.evidence import EvidenceState as state
from turbinia.evidence import RawDisk
from turbinia.workers.analysis.containerd import ContainerdEnumerationTask
from turbinia.workers.workers_test import TestTurbiniaTaskBase
from turbinia.workers import TurbiniaTaskResult


class ContainerdEnumerationTaskTest(TestTurbiniaTaskBase):
  """Tests for ContainerdEnumerationTask."""

  def setUp(self):
    super(ContainerdEnumerationTaskTest, self).setUp(
        task_class=ContainerdEnumerationTask,
        evidence_class=ContainerdContainer)
    self.task.output_dir = self.task.base_output_dir
    self.evidence = RawDisk(source_path='/rmk/data/containerd-evidence.dd')
    self.evidence.mount_path = '/mnt/mock'
    self.evidence.local_path = '/mnt/mock'
    self.evidence.state[state.MOUNTED] = True
    self.setResults(mock_run=False)

  def test_list_containers(self):
    """Tests method list_containers."""
    if not os.path.exists(self.evidence.mount_path):
      print(f'Mount path {self.evidence.mount_path} does not exist')
      return

    containers = self.task.list_containers(self.evidence, self.result)
    print(containers)

  def test_run(self):
    """Tests run method."""
    """
    if not os.path.exists(self.evidence.mount_path):
      print(f'Mount path{self.evidence.mount_path} does not exists')
      return
    """
    self.result = self.task.run(self.evidence, self.result)
    print('rest_run: ', self.result)


if __name__ == '__main__':
  unittest.main()
