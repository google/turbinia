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
"""Task for running Docker Explorer."""

from __future__ import unicode_literals

import json
import logging
import os
import subprocess

from turbinia import config
from turbinia import TurbiniaException
from turbinia.evidence import Directory
from turbinia.evidence import DockerContainer
from turbinia.processors import mount_local
from turbinia.workers import TurbiniaTask

log = logging.getLogger('turbinia')


class DockerContainersEnumerationTask(TurbiniaTask):
  """TODO"""

  def GetContainers(self, docker_dir):
    """TODO"""
    containers_info = None
    docker_explorer_command = ['sudo', '/usr/local/bin/de.py', '-r', docker_dir, 'list', 'all_containers']
    try:
      log.info('Running {0:s}'.format(' '.join(docker_explorer_command)))
      json_string = subprocess.check_output(docker_explorer_command)
    except Exception as e:
      raise TurbiniaException('Failed to run {0:s} {1!s}'.format(' '.join(docker_explorer_command), e))

    try:
      containers_info = json.loads(json_string)
    except ValueError as e:
      raise TurbiniaException(
          'Could not parse output of {0:s} : {1!s} .'.format(
              ' '.join(docker_explorer_command), e))

    return containers_info


  def run(self, evidence, result):
    """Run the TODO

    Args:
       evidence (Evidence object):  The evidence to process
       result (TurbiniaTaskResult): The object to place task results into.

    Returns:
      TurbiniaTaskResult object.
    """
    try:
      docker_dir_path = os.path.join(evidence.local_path, 'var', 'lib', 'docker')
      containers_info = self.GetContainers(docker_dir_path)
      for container_info in containers_info:
        container_id = container_info.get('container_id')
        container_evidence = DockerContainer(container_id=container_id, parent_evidence=evidence)
        result.add_evidence(container_evidence, evidence.config)
    except TurbiniaException as e:
      error_msg = 'TODO failed with {0!s}'.format(e)
      result.close(self, success=False, status=error_msg)

    result.close(self, success=True)
    return result
