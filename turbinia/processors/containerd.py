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
"""Evidence processor to mount local containerd containers."""

import logging
import os
import subprocess
import tempfile

from turbinia import config
from turbinia import TurbiniaException

log = logging.getLogger(__name__)


def PreprocessMountContainerdFS(image_path, namespace, container_id):
  """Mounts a containerd container filesystem locally.

  Args:
    image_path (str): Path where evidence disk is mounted.
    namespace (str): Namespace of the container to be mounted.
    container_id (str): ID of the container to be mounted.

  Returns:
    str: Path where container is mounted.
  """
  config.LoadConfig()
  mount_prefix = config.MOUNT_DIR_PREFIX

  containerd_dir = get_containerd_dir(image_path)
  if not os.path.isdir(containerd_dir):
    raise TurbiniaException(f'containerd path {containerd_dir} is not valid.')

  if os.path.exists(mount_prefix) and not os.path.isdir(mount_prefix):
    raise TurbiniaException(
        f'Mount directory {mount_prefix} is not a directory')

  if not os.path.exists(mount_prefix):
    log.info(f'Creating local mount parent directory {mount_prefix}')
    try:
      os.makedirs(mount_prefix)
    except OSError as e:
      raise TurbiniaException(
          f'Could not create mount directory {mount_prefix}: {e}') from e

  # Generate predectible containerd mount path
  containerd_mount_path = tempfile.mkdtemp(
      prefix=f'{namespace}_{container_id}_', dir=mount_prefix)

  ce_binary = '/opt/container-explorer/bin/ce'
  ce_support = '/opt/container-explorer/etc/supportcontainer.yaml'
  mount_cmd = [
      'sudo', ce_binary, '--support-container-data', ce_support, '-i',
      image_path, '-n', namespace, 'mount', container_id, containerd_mount_path
  ]

  log.info(f'Running: {mount_cmd}')
  try:
    subprocess.check_call(mount_cmd)
  except subprocess.CalledProcessError as e:
    raise TurbiniaException(
        f'Could not mount {namespace}:{container_id}: {e}') from e

  return containerd_mount_path


def get_containerd_dir(image_path):
  """Return containerd directory in mounted disk image.

  Args:
    image_path (str): Path where evidence disk is mounted.

  Returns:
    str: Path of containerd directory.
  """
  # Assuming containerd is installed on the default location
  # i.e. /var/lib/containerd
  containerd_dir = os.path.join(image_path, 'var', 'lib', 'containerd')

  # TODO(rmaskey): Handle if containerd is not installed on a default path.
  return containerd_dir
