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
import subprocess
import tempfile

from turbinia import config
from turbinia import TurbiniaException
from turbinia.evidence import ContainerdContainer
from turbinia.evidence import EvidenceState as state
from turbinia.workers import Priority
from turbinia.workers import TurbiniaTask

log = logging.getLogger('turbinia')

CE_BINARY = '/opt/container-explorer/bin/ce'
CE_SUPPORT_FILE = '/opt/container-explorer/etc/supportcontainer.yaml'


class ContainerdEnumerationTask(TurbiniaTask):
  """Enumerate containerd containers on Linux."""

  REQUIRED_STATES = [state.ATTACHED, state.MOUNTED]

  def list_containers(self, evidence, _, detailed_output=False):
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

    outputfile = tempfile.mkstemp()[1]
    list_cmd = [
        'sudo', CE_BINARY, '--support-container-data', CE_SUPPORT_FILE,
        '--output', 'json', '--output-file', outputfile, '--image-root',
        image_path, 'list', 'containers'
    ]
    log.info(f'Running {list_cmd}')

    try:
      #json_data = subprocess.check_output(list_cmd).decode('utf-8')
      subprocess.check_call(list_cmd)
      with open(outputfile, 'r') as fh:
        json_data = fh.read()
        if json_data:
          containers = json.loads(json_data)
    except json.JSONDecodeError as e:
      raise TurbiniaException(
          f'Error decoding container-explorer output: {e}') from e
    except subprocess.CalledProcessError as e:
      raise TurbiniaException(f'container-explorer return error: {e}') from e
    except FileNotFoundError as e:
      raise TurbiniaException(f'output file {outputfile} does not exist') from e

    return self._list_containers_result(containers, detailed_output)

  def _list_containers_result(self, containers, detailed_output):
    """ Determine and return containers information.

    Args:
      containers (list(dict)): Containers information
      detailed_output (bool): Check if detailed output is required.

    Returns:
      list(dict): List containers basic or complete output.
    """
    if not containers:
      return containers

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
    success = False
    report_data = []

    image_path = evidence.mount_path
    if not image_path:
      summary = f'Evidence {evidence.name}:{evidence.source_path} is not mounted'
      result.close(self, success=False, status=summary)
      return result

    try:
      # 1. List containers
      containers = self.list_containers(evidence, result)
      if not containers:
        result.close(self, success=True, status='Found 0 containers')
        return result

      container_ids = [x.get('ID') for x in containers]
      report_data.append(
          f'Found {len(container_ids)} containers: {", ".join(container_ids)}')

      # 2. Add containers as evidences
      for container in containers:
        namespace = container.get('Namespace')
        container_id = container.get('ID')
        container_type = container.get('ContainerType') or None

        if not namespace or not container_id:
          result.log(
              f'Value is empty. namespace={namespace}, container_id={container_id}'
          )
          report_data.append(
              f'Skipping container with empty value namespace ({namespace})'
              f' or container_id ({container_id})')
          continue

        # We want to process docker managed container using Docker-Explorer
        if container_type and container_type.lower() == 'docker':
          result.log(
              f'Skipping docker managed container {namespace}:{container_id}')
          report_data.append(
              f'Skipping docker managed container {namespace}:{container_id}')
          continue

        container_evidence = ContainerdContainer(
            namespace=namespace, container_id=container_id)

        result.add_evidence(container_evidence, evidence.config)
      summary = (
          f'Found {len(container_ids)} containers: {", ".join(container_ids)}')
      success = True
    except TurbiniaException as e:
      summary = f'Error enumerating containerd containers: {e}'
      report_data.append(summary)

    # 3. Prepare result
    result.report_priority = Priority.LOW
    result.report_data = '\n'.join(report_data)
    result.close(self, success=success, status=summary)
    return result
