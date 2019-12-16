# -*- coding: utf-8 -*-
# Copyright 2017 Google Inc.
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
"""Evidence processor to mount local Docker containers."""

from __future__ import unicode_literals

import logging
import os
import subprocess
import tempfile

from turbinia import config
from turbinia import TurbiniaException

log = logging.getLogger('turbinia')


def PreprocessMountDockerFS(docker_dir, container_id):
  """Mounts a Docker container Filesystem locally.

  We use subprocess to run the DockerExplorer script, instead of using the
  Python module, because we need to make sure all DockerExplorer code runs
  as root.

  Args:
    docker_dir(str): the root Docker directory.
    container_id(str): the complete ID of the container.

  Returns:
    The path to the mounted container file system, as a string.

  Raises:
    TurbiniaException: if there was an error trying to mount the filesystem.
  """
  # Most of the code is copied from PreprocessMountDisk
  # Only the mount command changes
  config.LoadConfig()
  mount_prefix = config.MOUNT_DIR_PREFIX

  if os.path.exists(mount_prefix) and not os.path.isdir(mount_prefix):
    raise TurbiniaException(
        'Mount dir {0:s} exists, but is not a directory'.format(mount_prefix))
  if not os.path.exists(mount_prefix):
    log.info('Creating local mount parent directory {0:s}'.format(mount_prefix))
    try:
      os.makedirs(mount_prefix)
    except OSError as e:
      raise TurbiniaException(
          'Could not create mount directory {0:s}: {1!s}'.format(
              mount_prefix, e))

  container_mount_path = tempfile.mkdtemp(prefix='turbinia', dir=mount_prefix)

  log.info(
      'Using docker_explorer to mount container {0:s} on {1:s}'.format(
          container_id, container_mount_path))
  de_binary = None
  for path in os.environ['PATH'].split(os.pathsep):
    tentative_path = os.path.join(path, 'de.py')
    if os.path.exists(tentative_path):
      de_binary = tentative_path
      break

  if not de_binary:
    raise TurbiniaException('Could not find docker-explorer script: de.py')

  # TODO(aarontp): Remove hard-coded sudo in commands:
  # https://github.com/google/turbinia/issues/73
  mount_cmd = [
      'sudo', de_binary, '-r', docker_dir, 'mount', container_id,
      container_mount_path
  ]
  log.info('Running: {0:s}'.format(' '.join(mount_cmd)))

  try:
    subprocess.check_call(mount_cmd)
  except subprocess.CalledProcessError as e:
    raise TurbiniaException(
        'Could not mount container {0:s}: {1!s}'.format(container_id, e))

  return container_mount_path
