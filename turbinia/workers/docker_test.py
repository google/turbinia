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
"""Tests for the Docker Containers Enumeration job."""

from __future__ import unicode_literals
from io import StringIO

import unittest
import textwrap
import mock

from turbinia.evidence import BulkExtractorOutput
from turbinia.evidence import PhotorecOutput
from turbinia.workers import docker
from turbinia.workers.workers_test import TestTurbiniaTaskBase
from turbinia.workers import TurbiniaTaskResult


class DockerTaskTest(TestTurbiniaTaskBase):
  """Tests for DockerContainersEnumerationTask."""

  def setUp(self):
    # pylint: disable=arguments-differ
    super(DockerTaskTest, self).setUp(
        task_class=docker.DockerContainersEnumerationTask,
        evidence_class=docker.DockerContainer)
    self.setResults(mock_run=False)
    self.task.output_dir = self.task.base_output_dir
    self.evidence.mount_path = 'non_existent'

  # pylint: disable=line-too-long
  @mock.patch('turbinia.state_manager.get_state_manager')
  @mock.patch(
      'turbinia.workers.docker.DockerContainersEnumerationTask.GetContainers')
  def testDockerContainersEnumerationRun(self, get_containers_mock, _):
    """Test DockerContainersEnumeration task run."""
    self.result.setup(self.task)

    get_containers_mock.return_value = [
        {
            'container_id': '12'
        },
        {
            'container_id': '3a'
        },
    ]
    result = self.task.run(self.evidence, self.result)

    # Ensure run method returns a TurbiniaTaskResult instance.
    self.assertIsInstance(result, TurbiniaTaskResult)
    self.assertEqual(result.task_name, 'DockerContainersEnumerationTask')
    self.assertEqual(len(result.evidence), 2)
    self.assertEqual(result.report_data, 'Found 2 containers: 12 3a')


if __name__ == '__main__':
  unittest.main()
