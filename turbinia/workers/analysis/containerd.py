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
"""Task for analyzing containerd containers."""

from __future__ import unicode_literals

import json
import logging
import os
import subprocess

from turbinia import config
from turbinia import TurbiniaException
from turbinia.evidence import ContainerdContainer
from turbinia.evidence import EvidenceState as state
from turbinia.evidence import ReportText
from turbinia.workers import Priority
from turbinia.workers import TurbiniaTask

log = logging.getLogger('turbinia')

CE_BINARY = '/opt/container-explorer/container-explorer'
CE_SUPPORT_FILE = '/opt/container-explorer/supportcontainer.yaml'


class ContainerdEnumerationTask(TurbiniaTask):
  """Enumerate containerd containers on Linux."""

  REQUIRED_STATE = [state.MOUNTED]

  def list_containers(self, evidence, result, detailed_output=False):
    """List containerd containers in the evidence.

    Args:
      evidence (Evidence): Input evidence to be processed.
      result (TurbiniaTaskResult): Object to store logs.

    Returns:
      list(dict): Containers information
    """
    config.LoadConfig()
    containers = None
    image_path = evidence.mount_path

    list_cmd = [
        'sudo', CE_BINARY, '--support-container-data', CE_SUPPORT_FILE,
        '--image-root', image_path, '--output', 'json', 'list', 'containers'
    ]

    try:
      json_data = subprocess.check_output(list_cmd).decode('utf-8')
      containers = json.loads(json_data)
    except json.JSONDecodeError as e:
      raise TurbiniaException(
          f'Error decoding container-explorer output: {e}') from e
    except subprocess.CalledProcessError as e:
      raise TurbiniaException(f'container-explorer return error: {e}') from e

    return self._list_containers_result(containers, detailed_output)

  def _list_containers_result(self, containers, detailed_output):
    """ Determine and return containers information.

    Args:
      containers (list(dict)): Containers information
      detailed_output (bool): Check if detailed output is required.

    Returns:
      list(dict): List containers basic or complete output.
    """
    if detailed_output:
      return containers

    basic_fields = [
        'Namespace', 'Image', 'ContainerType', 'ID', 'Hostname', 'CreatedAt'
        'Labels'
    ]
    basic_containers = []

    for container in containers:
      basic_container = {}
      for key, value in container.items():
        if key not in basic_fields:
          continue
        basic_container[key] = value
      basic_containers.append(basic_container)

    return basic_containers

  def run(self, evidence, result):
    """Run ContainerdEnumerationTask.

    Args:
      evidence (Evidence): Evidence to process.
      result (TurbiniaTaskResult): The object to place task result.

    Returns:
      TurbiniaTaskResult object
    """
    summary = ''
    report_data = []
    success = False

    image_path = evidence.mount_path

    try:
      # 1. List containers
      containers = self.list_containers(evidence, result)
      if not containers:
        result.close(self, success=False, status='Failed listing container')
        return result

      container_ids = [x.get('ID') for x in containers]
      summary = (
          f'Found {len(containers)} containers: {", ".join(container_ids)}')

      # 2. Add containers as evidences
      for container in containers:
        namespace = container.get('Namespace')
        container_id = container.get('ID')

        container_evidence = ContainerdContainer(
            image_path=image_path, namespace=namespace,
            container_id=container_id)
        report_data.append(
            'Created evidence for {0:s}:{1:s} mounted at {2!s}'.format(
                namespace, container_id, container_evidence.mount_path))

        result.add_evidence(container_evidence, evidence.config)
      success = True
    except TurbiniaException as e:
      summary = f'Error enumerating containerd containers: {e}'

    # 3. Prepare result
    result.report_priority = Priority.LOW
    result.report_data = ', '.join(report_data)
    result.close(self, success=success, status=summary)
    return result
