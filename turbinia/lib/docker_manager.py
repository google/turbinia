# -*- coding: utf-8 -*-
# Copyright 2020 Google Inc.
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
"""Library to handle docker related queries."""

from __future__ import unicode_literals

import logging
import codecs
import os
import stat
import docker

from turbinia import TurbiniaException

log = logging.getLogger('turbinia')


def IsBlockDevice(path):
  """Checks path to determine whether it is a block device.

  Args:
      path: String of path to check.

  Returns:
      Bool indicating success.
  """
  if not os.path.exists(path):
    return False
  mode = os.stat(path).st_mode
  return stat.S_ISBLK(mode)


class DockerManager(object):
  """Class handling Docker management."""

  def __init__(self):
    """Initialize the Docker manager client."""
    self.client = self._create_client()

  def _create_client(self):
    """Creates a Docker client.

    Initializes a connection to the Docker daemon using
    preconfigured Docker environment variables.

    Returns:
      docker_client(DockerClient): The Docker daemon client.

    Raises:
      TurbiniaException: If the Docker daemon could not be connected to.
    """
    try:
      docker_client = docker.from_env()
    except docker.errors.APIError as exception:
      raise TurbiniaException(
          'An issue has occured connecting to the Docker daemon: {0!s}'.format(
              exception))
    return docker_client

  def verify_image(self, image_id):
    """Verify that the Docker image exists.

    Args:
      image_id(str): The short image id to check for.

    Returns:
      image_verif(Image): The Image object.

    Raises:
      TurbiniaException: If the Docker image is not found.
    """
    try:
      image_verif = self.client.images.get(image_id)
    except docker.errors.ImageNotFound as exception:
      message = 'The Docker image {0!s} could not be found: {1!s}'
      raise TurbiniaException(message.format(image_id, exception))
    return image_verif

  def list_images(self, filters=None):
    """Lists all available Docker images.

    Args:
     filters(str): If provided, will return a subset of the Images data.
        Allowed values are 'short_id' and 'id'.

    Returns:
      images(list): A list of available Docker images.

    Raises:
      TurbiniaException: If an error occured retrieving the images.
    """
    accepted_vars = ['short_id', 'id']
    try:
      images = self.client.images.list()
      if filters in accepted_vars:
        # short_id and id will always start with sha256:
        images = [
            getattr(img, filters).replace('sha256:', '') for img in images
        ]
    except docker.errors.APIError as exception:
      raise TurbiniaException(
          'An error occured retrieving the images: {0!s}'.format(exception))
    return images


class ContainerManager(DockerManager):
  """Class representing Docker containers.

  Attributes:
    image_id(str): Docker image id.
  """

  def __init__(self, image_id):
    """Initialize the ContainerManager object.

    Args:
      image_id(str): The image id to create a container from.
    """
    super(ContainerManager, self).__init__()
    self.image_id = self.verify_image(image_id)

  def _create_mount_points(self, mount_paths):
    """Creates file and device mounting arguments.

    The arguments will be passed into the container and all device blocks
    will be mounted as ro while file paths would be mounted as rw.

    Attributes:
      mount_paths(list): The paths on the host system to be mounted.

    Returns:
      device_paths(list): device blocks that will be mounted.
      file_paths(dict): file paths that will be mounted.
    """
    device_paths = []
    file_paths = {}

    for mpath in mount_paths:
      if mpath not in file_paths.keys() or mpath not in device_paths:
        if IsBlockDevice(mpath):
          formatted_path = '{0:s}:{0:s}:{1:s}'.format(mpath, 'r')
          device_paths.append(formatted_path)
        else:
          file_paths[mpath] = {'bind': mpath, 'mode': 'rw'}
    return device_paths, file_paths

  def execute_container(self, cmd, mount_paths=None, **kwargs):
    """Executes a Docker container.

    A new Docker container will be created from the image id,
    executed, and then removed.

    Attributes:
      cmd(str|list): command to be executed.
      mount_paths(list): A list of paths to mount to the container.
      **kwargs: Any additional keywords to pass to the container.

    Returns:
      stdout(str): stdout of the container.
      stderr(str): stderr of the container.
      ret(str): the return code of process run.

    Raises:
      TurbiniaException: If an error occured with the Docker container.
    """
    container = None
    args = {}
    stdout = ''

    # Create the device and file mount paths
    if mount_paths:
      device_paths, file_paths = self._create_mount_points(mount_paths)
      args['devices'] = device_paths if device_paths else []
      args['volumes'] = file_paths if file_paths else []

    # Add any additional arguments
    for key, value in kwargs.items():
      args[key] = value

    try:
      container = self.client.containers.create(self.image_id, cmd, **args)
      container.start()
      # Stream program stdout from container
      stdstream = container.logs(stream=True)
      for stdo in stdstream:
        stdo = codecs.decode(stdo, 'utf-8').strip()
        log.info(stdo)
        stdout += stdo
      results = container.wait()
    except docker.errors.APIError as exception:
      if container:
        container.remove(v=True)
      message = (
          'An error has occured with the container: {0!s}'.format(exception))
      log.error(message)
      raise TurbiniaException(message)

    stderr, ret = results['Error'], results['StatusCode']
    if container:
      container.remove(v=True)

    return stdout, stderr, ret
