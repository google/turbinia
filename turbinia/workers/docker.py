# -*- coding: utf-8 -*-
# Copyright 2015 Google Inc.
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
"""Task for running docker-explorer."""

from __future__ import unicode_literals

import json
import logging
import os

from docker_explorer import explorer
from docker_explorer.errors import BadStorageException

from turbinia import TurbiniaException
from turbinia.evidence import DockerContainer
from turbinia.processors import mount_local
from turbinia.workers import TurbiniaTask

log = logging.getLogger('turbinia')


class DockerContainersEnumerationTask(TurbiniaTask):
  """Enumerates Docker containers on Linux"""

  def GetContainers(self, evidence):
    """Lists the containers from an input Evidence.

    Args:
      evidence (Evidence): the input Evidence.

    Returns:
      list(docker_explorer.Container): list of containers objects.

    Raises:
      TurbiniaException: when the docker-explorer tool failed to run.
    """

    mount_path = evidence.local_path
    if type(evidence).__name__ == 'RawDisk':
      # RawDisk doesn't mount the underlying partition
      mount_path = mount_local.PreprocessMountDisk(
          evidence.loopdevice_path, evidence.mount_partition)

    docker_dir = os.path.join(mount_path, 'var', 'lib', 'docker')

    containers_info = []
    log.info('Searching for Docker containers in {0}'.format(docker_dir))
    log.info('things there: {0}'.format(' '.join(os.listdir(docker_dir))))
    try:
      explorer_object = explorer.Explorer()
      explorer_object.SetDockerDirectory(docker_dir)
      containers_info = explorer_object.GetAllContainers()
    except BadStorageException as e:
      mount_local.PostprocessUnmountPath(mount_path)
      log.info('error docker pute {0!s}'.format(e))
      raise TurbiniaException(
          'Failed to get Docker containers: {0!s}'.format(e))

    mount_local.PostprocessUnmountPath(mount_path)
    return containers_info

  def run(self, evidence, result):
    """Run the docker-explorer tool to list containerss.

    Args:
       evidence (Evidence object):  The evidence to process
       result (TurbiniaTaskResult): The object to place task results into.

    Returns:
      TurbiniaTaskResult object.
    """

    status_report = ''
    success = False

    found_containers = []
    try:
      containers_info = self.GetContainers(evidence)
      for container_info in containers_info:
        container_id = container_info.container_id
        found_containers.append(container_id)
        container_evidence = DockerContainer(container_id=container_id)
        result.add_evidence(container_evidence, evidence.config)
      success = True
    except TurbiniaException as e:
      status_report = 'Error enumerating Docker containers: {0!s}'.format(e)

    status_report = 'Found {0!s} containers: {1}'.format(
        len(found_containers), ' '.join(found_containers))

    result.close(self, success=success, status=status_report)

    return result
