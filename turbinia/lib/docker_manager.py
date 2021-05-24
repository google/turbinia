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
import json
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


def GetDockerPath(mount_path):
  """Retrieves the Docker installation path.

  Args:
    mount_path(str): The mount path of the Evidence object.

  Returns:
    docker_path(str): The Docker installation path.
  """
  docker_path = None
  etc_path = os.path.join(mount_path, 'etc/docker/daemon.json')
  if os.path.exists(etc_path):
    try:
      with open(etc_path) as etc_handle:
        json_obj = json.loads(etc_handle.read())['data-root']
        # Remove starting / so paths can join
        if json_obj.startswith('/'):
          json_obj = json_obj[1:]
        docker_path = os.path.join(mount_path, json_obj)
    except KeyError as exception:
      log.error(
          'Error parsing the Docker daemon config file due to: {0:s}. '
          'Using default Docker installation path'.format(str(exception)))

  # If file not found or error occurred parsing Docker config file.
  if docker_path is None:
    log.warning(
        'Docker daemon confile file not found. '
        'Using default Docker installation path.')
    docker_path = os.path.join(mount_path, 'var/lib/docker')
  return docker_path


class DockerManager:
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
          'An issue has occurred connecting to the Docker daemon: {0!s}'.format(
              exception))
    except docker.errors.DockerException as exception:
      raise TurbiniaException(
          'An issue has occurred connecting to the Docker daemon: {0!s}'.format(
              exception))
    return docker_client

  def get_image(self, image_id):
    """Retrieve the Docker Image object.

    Args:
      image_id(str): The short image id.

    Returns:
      image(Image): The Image object.

    Raises:
      TurbiniaException: If the Docker Image is not found.
    """
    try:
      image = self.client.images.get(image_id)
    except docker.errors.ImageNotFound as exception:
      message = 'The Docker image {0!s} could not be found: {1!s}'
      raise TurbiniaException(message.format(image_id, exception))
    return image

  def list_images(self, return_filter=None):
    """Lists all available Docker images.

    Args:
     return_filter(str): If provided, will return a subset of the Images data.
        Allowed values are 'short_id' and 'id'.

    Returns:
      list: containing:
        Images: The Image objects
        str: The Image ids if a filter was specified.

    Raises:
      TurbiniaException: If an error occurred retrieving the images.
    """
    accepted_vars = ['short_id', 'id']
    try:
      images = self.client.images.list()
      if return_filter in accepted_vars:
        # short_id and id will always start with sha256:
        images = [
            getattr(img, return_filter).replace('sha256:', '') for img in images
        ]
    except docker.errors.APIError as exception:
      raise TurbiniaException(
          'An error occurred retrieving the images: {0!s}'.format(exception))
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
    self.image = self.get_image(image_id)

  def _create_mount_points(self, mount_paths, mode='rw'):
    """Creates file and device mounting arguments.

    The arguments will be passed into the container with the appropriate
    mounting parameters. All device blocks will be mounted as read only,
    regardless of the specified mode.

    Attributes:
      mount_paths(list): The paths on the host system to be mounted.
      mode(str): The mode the path will be mounted in. The acceptable
                 parameters are rw for read write and ro for read only.

    Returns:
      tuple: containing:
        list: The device blocks that will be mounted.
        dict: The file paths that will be mounted.

    Raises:
      TurbiniaException: If an incorrect mode was passed.
    """
    accepted_vars = ['rw', 'ro']
    device_paths = []
    file_paths = {}

    if mode in accepted_vars:
      for mpath in mount_paths:
        device_mpath = '{0:s}:{0:s}:{1:s}'.format(str(mpath), 'r')
        if mpath not in file_paths.keys() and device_mpath not in device_paths:
          if IsBlockDevice(mpath):
            device_paths.append(device_mpath)
          else:
            file_paths[mpath] = {'bind': mpath, 'mode': mode}
    else:
      raise TurbiniaException(
          'An incorrect mode was passed: {0:s}. Unable to create the correct '
          'mount points for the Docker container.'.format(mode))

    return device_paths, file_paths

  def execute_container(
      self, cmd, shell=False, ro_paths=None, rw_paths=None, timeout_limit=3600,
      **kwargs):
    """Executes a Docker container.

    A new Docker container will be created from the image id,
    executed, and then removed.

    Attributes:
      cmd(str|list): command to be executed.
      shell (bool): Whether the cmd is in the form of a string or a list.
      mount_paths(list): A list of paths to mount to the container.
      timeout_limit(int): The number of seconds before killing a container.
      **kwargs: Any additional keywords to pass to the container.

    Returns:
      stdout(str): stdout of the container.
      stderr(str): stderr of the container.
      ret(int): the return code of the process run.

    Raises:
      TurbiniaException: If an error occurred with the Docker container.
    """
    container = None
    args = {}
    stdout = ''

    # Override the entrypoint to /bin/sh
    kwargs['entrypoint'] = '/bin/sh'
    if shell:
      cmd = '-c ' + '\"{0:s}\"'.format(cmd)
    else:
      cmd = ' '.join(cmd)
      cmd = '-c ' + '\"{0:s}\"'.format(cmd)

    # Create the device and file mount paths
    device_paths = []
    file_paths = {}
    if rw_paths:
      dwpath, fwpath = self._create_mount_points(rw_paths)
      device_paths.extend(dwpath)
      file_paths.update(fwpath)
    if ro_paths:
      drpath, frpath = self._create_mount_points(ro_paths, mode='ro')
      device_paths.extend(drpath)
      file_paths.update(frpath)

    args['devices'] = device_paths
    args['volumes'] = file_paths

    # Add any additional arguments
    for key, value in kwargs.items():
      args[key] = value

    try:
      container = self.client.containers.create(self.image, cmd, **args)
      container.start()
      # Stream program stdout from container
      stdstream = container.logs(stream=True)
      for stdo in stdstream:
        stdo = codecs.decode(stdo, 'utf-8').strip()
        log.debug(stdo)
        stdout += stdo
      results = container.wait(timeout=timeout_limit)
    except docker.errors.APIError as exception:
      if container:
        container.remove(v=True)
      message = (
          'An error has occurred with the container: {0!s}'.format(exception))
      log.error(message)
      raise TurbiniaException(message)

    stderr, ret = results['Error'], results['StatusCode']
    if container:
      container.remove(v=True)

    return stdout, stderr, ret
