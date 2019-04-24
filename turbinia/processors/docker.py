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

from docker_explorer import container
from docker_explorer import explorer

from turbinia import config
from turbinia import TurbiniaException

log = logging.getLogger('turbinia')


def PreprocessMountDockerFS(docker_dir, container_id):
  """Mounts a Docker container Filesystem locally.

  Args:
    docker_dir: the root Docker directory, as string.
    container_id: the complete ID of the container, as string.

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

  log.info('Using docker_explorer to mount container {0:s} on {1:s}'.format(
      container_id, container_mount_path))
  try:
    explorer_object = explorer.Explorer()
    explorer_object.SetDockerDirectory(docker_dir)
    container_object = explorer_object.GetContainer(container_id)
    container_object.Mount(container_mount_path)
  except Exception as e:
    raise TurbiniaException('Could not mount container: {0!s}'.format(e))

  return mount_path
