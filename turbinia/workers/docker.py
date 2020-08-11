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
import subprocess

from turbinia import TurbiniaException
from turbinia.evidence import DockerContainer
from turbinia.evidence import EvidenceState as state
from turbinia.workers import Priority
from turbinia.workers import TurbiniaTask
from turbinia.lib.docker_manager import GetDockerPath
from turbinia import config

log = logging.getLogger('turbinia')


class DockerContainersEnumerationTask(TurbiniaTask):
  """Enumerates Docker containers on Linux"""

  REQUIRED_STATES = [
      state.ATTACHED, state.MOUNTED, state.PARENT_ATTACHED, state.PARENT_MOUNTED
  ]

  def GetContainers(self, evidence):
    """Lists the containers from an input Evidence.

    We use subprocess to run the DockerExplorer script, instead of using the
    Python module, because we need to make sure all DockerExplorer code runs
    as root.

    Args:
      evidence (Evidence): the input Evidence.

    Returns:
      a list(dict) containing information about the containers found.

    Raises:
      TurbiniaException: when the docker-explorer tool failed to run.
    """
    config.LoadConfig()
    docker_dir = GetDockerPath(evidence.mount_path)

    containers_info = None

    # TODO(rgayon): use docker-explorer exposed constant when
    # https://github.com/google/docker-explorer/issues/80 is in.
    docker_explorer_command = [
        'sudo', 'de.py', '-r', docker_dir, 'list', 'all_containers'
    ]
    if config.DEBUG_TASKS or evidence.config.get('debug_tasks'):
      docker_explorer_command.append('-d')
    log.info('Running {0:s}'.format(' '.join(docker_explorer_command)))
    try:
      json_string = subprocess.check_output(docker_explorer_command).decode(
          'utf-8')
    except json.JSONDecodeError as e:
      raise TurbiniaException(
          'Error decoding JSON output from de.py: {0!s}'.format(e))
    except subprocess.CalledProcessError as e:
      raise TurbiniaException('de.py returned an error: {0!s}'.format(e))

    containers_info = json.loads(json_string)

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

    status_report = (
        'Error enumerating Docker containers, evidence has no mounted '
        'filesystem')
    found_containers = []
    try:
      containers_info = self.GetContainers(evidence)
      for container_info in containers_info:
        container_id = container_info.get('container_id')
        found_containers.append(container_id)
        container_evidence = DockerContainer(container_id=container_id)
        result.add_evidence(container_evidence, evidence.config)
      success = True
      status_report = 'Found {0!s} containers: {1:s}'.format(
          len(found_containers), ' '.join(found_containers))
    except TurbiniaException as e:
      status_report = 'Error enumerating Docker containers: {0!s}'.format(e)

    result.report_priority = Priority.LOW
    result.report_data = status_report
    result.close(self, success=success, status=status_report)
    return result
