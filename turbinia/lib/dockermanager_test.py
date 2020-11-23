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
"""Tests for docker_manager module."""

from __future__ import unicode_literals

import unittest
import codecs
import mock
import docker
import tempfile
import os

from turbinia.lib import docker_manager
from turbinia import TurbiniaException


class MockImage:
  """Mock class for a Docker image.

  Attributes:
    short_id(str): The short id of the image.
    id(str): The full id of the image.
  """

  def __init__(self, id, short_id):
    """Initialization of the MockImage class."""
    self.id = 'sha256:{0:s}'.format(id)
    self.short_id = 'sha256:{0:s}'.format(short_id)


class MockContainer:
  """Mock class for a Docker container.

  Attributes:
    s_start(str): sample output for start method.
    s_logs(list): sample output for logs method.
    s_wait(str): sample output for wait method.
    s_remove(str): sample output for remove method.
  """

  def __init__(self, s_start=None, s_logs=None, s_wait=None, s_remove=None):
    """Initialization of the MockContainer class."""
    self.s_start = s_start
    self.s_logs = s_logs
    self.s_wait = s_wait
    self.s_remove = s_remove

  def start(self):
    """Mock method of container.start()"""
    return self.s_start

  def logs(self, stream=None):
    """Mock method of container.logs()"""
    return self.s_logs

  def wait(self):
    """Mock method of container.wait()"""
    return self.s_wait

  def remove(self, v=None):
    """Mock method of container.remove()"""
    return self.s_remove


class TestDockerManager(unittest.TestCase):
  """Test DockerManager class."""

  @mock.patch('turbinia.lib.docker_manager.docker')
  def setUp(self, mock_docker):
    mock_docker.from_env.return_value = docker.client.DockerClient
    self.docker_mgr = docker_manager.DockerManager()

  def testDockerManagerInit(self):
    """Tests __init__ method of DockerManager."""
    # Test that a DockerClient is being returned
    assert self.docker_mgr.client == docker.client.DockerClient

  def testVerifyImages(self):
    """Tests DockerManager.get_image() method."""
    # Test normal execution.
    test_img = '1234'
    self.docker_mgr.client = mock.MagicMock()
    self.docker_mgr.client.images.get.return_value = test_img
    assert test_img == self.docker_mgr.get_image(test_img)

    # Ensure exception is being handled when image doesn't exist.
    self.docker_mgr.client.images.get.side_effect = docker.errors.ImageNotFound(
        'mock test fail.')
    self.assertRaises(TurbiniaException, self.docker_mgr.get_image, test_img)

  def testListImages(self):
    """Tests DockerManager.list_images() method."""
    id_smpl = ['123456', '234567']
    sid_smpl = ['123', '234']
    img_sample = [
        MockImage(id_smpl[0], sid_smpl[0]),
        MockImage(id_smpl[1], sid_smpl[1])
    ]

    # Ensure list is being returned.
    self.docker_mgr.client = mock.MagicMock()
    self.docker_mgr.client.images.list.return_value = img_sample
    assert isinstance(self.docker_mgr.list_images(), list)

    # Ensure values are properly being stripped off.
    assert self.docker_mgr.list_images(return_filter='short_id') == sid_smpl
    assert self.docker_mgr.list_images(return_filter='id') == id_smpl

    # Ensure img object is being returned if incorrect filter is provided.
    img = self.docker_mgr.list_images(return_filter='non_exist')
    assert isinstance(img[0], MockImage)

    # Ensure exception is being handled.
    self.docker_mgr.client.images.list.side_effect = docker.errors.APIError(
        'mock test fail.')
    self.assertRaises(TurbiniaException, self.docker_mgr.list_images)


class TestContainerManager(unittest.TestCase):
  """Test ContainerManager class."""

  @mock.patch('turbinia.lib.docker_manager.docker')
  @mock.patch('turbinia.lib.docker_manager.DockerManager.get_image')
  def setUp(self, mock_get, mock_docker):
    self.test_img = '1234'
    mock_docker.from_env.return_value = docker.client.DockerClient
    mock_get.return_value = self.test_img
    self.container_mgr = docker_manager.ContainerManager(self.test_img)

  def testContainerManagerInit(self):
    """Tests __init__ method of ContainerManager."""
    # Ensure correct instance and image id
    assert self.container_mgr.client == docker.client.DockerClient
    assert self.container_mgr.image == self.test_img

  @mock.patch('turbinia.lib.docker_manager.IsBlockDevice')
  def testCreateMountPoints(self, mock_blockcheck):
    """Tests ContainerManager._create_mount_points() method."""
    # Ensure correct device formatting.
    mock_blockcheck.return_value = True
    device_smpl = ['/path/to/device']
    device_formatted = ['{0:s}:{0:s}:r'.format(device_smpl[0])]
    device_paths, _ = self.container_mgr._create_mount_points(device_smpl)
    assert device_formatted == device_paths

    # Ensure correct file path formmating.
    mock_blockcheck.return_value = False
    file_smpl = ['/path/to/file']
    file_formatted = {}
    file_formatted[file_smpl[0]] = {'bind': file_smpl[0], 'mode': 'rw'}
    _, file_paths = self.container_mgr._create_mount_points(file_smpl)
    assert file_formatted == file_paths

  def testExecuteContainer(self):
    """Tests ContainerManager.execute_container() method."""
    # sample output
    s_logs = [b'this', b'is', b'a', b'mock', b'test']
    s_wait = {'Error': None, 'StatusCode': 0}
    self.container_mgr.client = mock.MagicMock()
    self.container_mgr.client.containers.create.return_value = MockContainer(
        s_logs=s_logs, s_wait=s_wait)
    stdout, stderr, ret = self.container_mgr.execute_container('cm', shell=True)

    # Ensure correct output
    out = [codecs.decode(w, 'utf-8') for w in s_logs]
    assert stdout == ''.join(out)
    assert stderr == s_wait['Error']
    assert ret == s_wait['StatusCode']

    # Ensure exception is being handled
    exception = docker.errors.APIError('mock test fail.')
    self.container_mgr.client.containers.create.side_effect = exception
    self.assertRaises(
        TurbiniaException, self.container_mgr.execute_container, 'cmd',
        shell=True)


class TestDockerManagerFunc(unittest.TestCase):
  """Tests docker_manager's functions

  Attributes:
    base_output(str): The base output directory of the config file
    output_path1(str): First sample Docker config file
    output_path2(str): Second sample Docker config file
    remove_files(list(str)): Files that will be removed after the test run
  """

  def setUp(self):
    self.base_output = tempfile.mkdtemp()
    self.output_path1 = os.path.join(self.base_output, 'daemon1.json')
    with open(self.output_path1, 'w') as out1:
      out1.write('{"data-root": "/path/to/docker"}')

    self.output_path2 = os.path.join(self.base_output, 'daemon2.json')
    with open(self.output_path2, 'w') as out2:
      out2.write('{"blah2": "/path/to/docker"}')

    self.remove_files = [self.output_path1, self.output_path2]

  def tearDown(self):
    for remove_file in self.remove_files:
      if os.path.exists(remove_file):
        os.remove(remove_file)

    os.rmdir(self.base_output)

  @mock.patch('os.path.join')
  def testGetDockerPath(self, mock_join):
    """Tests the GetDockerPath() method."""
    # Test successful run
    mock_join.return_value = self.output_path1
    docker_path1 = docker_manager.GetDockerPath(self.output_path1)
    return_val1 = os.path.join(self.output_path1, 'path/to/docker')
    self.assertEqual(docker_path1, return_val1)

    # Test config parsing fail
    mock_join.return_value = self.output_path2
    docker_path2 = docker_manager.GetDockerPath(self.output_path2)
    return_val2 = os.path.join(self.output_path2, 'var/lib/docker')
    self.assertEqual(docker_path2, return_val2)

    # Test file not found.
    docker_path3 = docker_manager.GetDockerPath('blah')
    self.assertEqual(docker_path3, return_val2)
