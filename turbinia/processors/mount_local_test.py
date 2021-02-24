# -*- coding: utf-8 -*-
# Copyright 2020 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Tests for mount_local processor."""

from __future__ import unicode_literals

import os
from subprocess import CalledProcessError
import unittest

import mock

from turbinia import TurbiniaException
from turbinia.processors import mount_local


def _mock_returns(*args, **kwargs):
  """Mock return values."""
  if args[0] == '/dev/loop0p4':
    return False
  return True


class MountLocalProcessorTest(unittest.TestCase):
  """Tests for mount_local processor."""

  @mock.patch('turbinia.processors.mount_local.config')
  @mock.patch('tempfile.mkdtemp')
  @mock.patch('subprocess.check_call')
  @mock.patch('os.path.isdir')
  @mock.patch('os.path.exists')
  @mock.patch('os.makedirs')
  def testPreprocessBitLocker(
      self, _, mock_path_exists, mock_path_isdir, mock_subprocess, mock_mkdtemp,
      mock_config):
    """Test PreprocessBitLocker method."""
    mock_config.MOUNT_DIR_PREFIX = '/mnt/turbinia'
    mock_path_exists.side_effect = _mock_returns
    mock_mkdtemp.return_value = '/mnt/turbinia/turbinia0ckdntz0'

    current_path = os.path.abspath(os.path.dirname(__file__))
    source_path = os.path.join(
        current_path, '..', '..', 'test_data', 'tsk_volume_system.raw')
    credentials = [{'credential_type': 'password', 'credential_data': '123456'}]

    mock_path_isdir.return_value = True
    device = mount_local.PreprocessBitLocker(
        source_path, partition_offset=65536, credentials=credentials)
    expected_args = [
        'sudo', 'bdemount', '-o', '65536', '-p', '123456', '-X', 'allow_other',
        source_path, '/mnt/turbinia/turbinia0ckdntz0'
    ]
    mock_subprocess.assert_called_once_with(expected_args)
    self.assertEqual(device, '/mnt/turbinia/turbinia0ckdntz0/bde1')

    # Test with recovery password
    mock_subprocess.reset_mock()
    credentials = [{
        'credential_type': 'recovery_password',
        'credential_data': '123456'
    }]
    mount_local.PreprocessBitLocker(
        source_path, partition_offset=65536, credentials=credentials)
    expected_args = [
        'sudo', 'bdemount', '-o', '65536', '-r', '123456', '-X', 'allow_other',
        source_path, '/mnt/turbinia/turbinia0ckdntz0'
    ]
    mock_subprocess.assert_called_once_with(expected_args)

    # Test if source does not exist
    with self.assertRaises(TurbiniaException):
      mount_local.PreprocessBitLocker(
          '/dev/loop0p4', partition_offset=65536, credentials=credentials)

    # Test if mount path not directory
    mock_path_isdir.return_value = False
    with self.assertRaises(TurbiniaException):
      mount_local.PreprocessBitLocker(
          source_path, partition_offset=65536, credentials=credentials)
    mock_path_isdir.return_value = True

    # Test decryption failure
    mock_subprocess.reset_mock()
    mock_subprocess.side_effect = CalledProcessError(1, 'bdemount')
    device = mount_local.PreprocessBitLocker(
        source_path, partition_offset=65536, credentials=credentials)
    self.assertEqual(device, None)

    # Test with unsupported credential type
    mock_subprocess.reset_mock()
    credentials = [{
        'credential_type': 'startup_key',
        'credential_data': 'key.BEK'
    }]
    mount_local.PreprocessBitLocker(
        source_path, partition_offset=65536, credentials=credentials)
    mock_subprocess.assert_not_called()

  @mock.patch('subprocess.check_output')
  def testPreprocessLosetup(self, mock_subprocess):
    """Test PreprocessLosetup method."""
    current_path = os.path.abspath(os.path.dirname(__file__))
    source_path = os.path.join(
        current_path, '..', '..', 'test_data', 'tsk_volume_system.raw')
    mock_subprocess.return_value = '/dev/loop0'
    device = mount_local.PreprocessLosetup(source_path)
    expected_args = ['sudo', 'losetup', '--show', '--find', '-r', source_path]
    mock_subprocess.assert_called_once_with(
        expected_args, universal_newlines=True)
    self.assertEqual(device, '/dev/loop0')

    # Test mount partition
    mock_subprocess.reset_mock()
    mock_subprocess.return_value = '/dev/loop0'
    device = mount_local.PreprocessLosetup(
        source_path, partition_offset=180224, partition_size=1294336)
    expected_args = [
        'sudo', 'losetup', '--show', '--find', '-r', '-o', '180224',
        '--sizelimit', '1294336', source_path
    ]
    mock_subprocess.assert_called_once_with(
        expected_args, universal_newlines=True)
    self.assertEqual(device, '/dev/loop0')

    # Test losetup failure
    mock_subprocess.side_effect = CalledProcessError(1, 'losetup')
    with self.assertRaises(TurbiniaException):
      mount_local.PreprocessLosetup(source_path)

    # Test if source doesn't exist
    source_path = 'test.dd'
    with self.assertRaises(TurbiniaException):
      mount_local.PreprocessLosetup(source_path)

  @mock.patch('turbinia.processors.mount_local.config')
  @mock.patch('tempfile.mkdtemp')
  @mock.patch('subprocess.check_output')
  @mock.patch('subprocess.check_call')
  @mock.patch('os.path.isdir')
  @mock.patch('os.path.exists')
  @mock.patch('os.makedirs')
  def testPreprocessMountDisk(
      self, _, mock_path_exists, mock_path_isdir, mock_subprocess,
      mock_filesystem, mock_mkdtemp, mock_config):
    """Test PreprocessMountDisk method."""
    mock_config.MOUNT_DIR_PREFIX = '/mnt/turbinia'
    mock_path_exists.side_effect = _mock_returns
    mock_filesystem.return_value = b'ext4'
    mock_mkdtemp.return_value = '/mnt/turbinia/turbinia0ckdntz0'

    # Test partition number too high
    with self.assertRaises(TurbiniaException):
      mount_local.PreprocessMountDisk(['/dev/loop0p1'], 2)

    # Test bad partition number
    with self.assertRaises(TurbiniaException):
      mount_local.PreprocessMountDisk(['/dev/loop0p1'], 0)

    # Test partition path doesn't exist
    with self.assertRaises(TurbiniaException):
      mount_local.PreprocessMountDisk(['/dev/loop0p4'], 1)

    # Test mount prefix is not directory
    mock_path_isdir.return_value = False
    with self.assertRaises(TurbiniaException):
      mount_local.PreprocessMountDisk(['/dev/loop0p1'], 1)
    mock_path_isdir.return_value = True

    # Test ext4
    mount_path = mount_local.PreprocessMountDisk(['/dev/loop0p1'], 1)
    expected_args = [
        'sudo', 'mount', '-o', 'ro', '-o', 'noload', '/dev/loop0p1',
        '/mnt/turbinia/turbinia0ckdntz0'
    ]
    mock_subprocess.assert_called_once_with(expected_args)
    self.assertEqual(mount_path, '/mnt/turbinia/turbinia0ckdntz0')

    # Test mount failure
    mock_subprocess.reset_mock()
    mock_subprocess.side_effect = CalledProcessError(1, 'mount')
    with self.assertRaises(TurbiniaException):
      mount_local.PreprocessMountDisk(['/dev/loop0p1'], 1)

  @mock.patch('turbinia.processors.mount_local.config')
  @mock.patch('tempfile.mkdtemp')
  @mock.patch('subprocess.check_output')
  @mock.patch('subprocess.check_call')
  @mock.patch('os.path.isdir')
  @mock.patch('os.path.exists')
  @mock.patch('os.makedirs')
  def testPreprocessMountPartition(
      self, _, mock_path_exists, mock_path_isdir, mock_subprocess,
      mock_filesystem, mock_mkdtemp, mock_config):
    """Test PreprocessMountPartition method."""
    mock_config.MOUNT_DIR_PREFIX = '/mnt/turbinia'
    mock_path_exists.side_effect = _mock_returns
    mock_filesystem.return_value = b'ext4'
    mock_mkdtemp.return_value = '/mnt/turbinia/turbinia0ckdntz0'

    # Test partition path doesn't exist
    with self.assertRaises(TurbiniaException):
      mount_local.PreprocessMountPartition('/dev/loop0p4')

    # Test mount prefix is not directory
    mock_path_isdir.return_value = False
    with self.assertRaises(TurbiniaException):
      mount_local.PreprocessMountPartition('/dev/loop0')
    mock_path_isdir.return_value = True

    # Test ext4
    mount_path = mount_local.PreprocessMountPartition('/dev/loop0')
    expected_args = [
        'sudo', 'mount', '-o', 'ro', '-o', 'noload', '/dev/loop0',
        '/mnt/turbinia/turbinia0ckdntz0'
    ]
    mock_subprocess.assert_called_once_with(expected_args)
    self.assertEqual(mount_path, '/mnt/turbinia/turbinia0ckdntz0')

    # Test xfs
    mock_subprocess.reset_mock()
    mock_filesystem.return_value = b'xfs'
    mount_path = mount_local.PreprocessMountPartition('/dev/loop0')
    expected_args = [
        'sudo', 'mount', '-o', 'ro', '-o', 'norecovery', '/dev/loop0',
        '/mnt/turbinia/turbinia0ckdntz0'
    ]
    mock_subprocess.assert_called_once_with(expected_args)
    self.assertEqual(mount_path, '/mnt/turbinia/turbinia0ckdntz0')

    # Test mount failure
    mock_subprocess.reset_mock()
    mock_subprocess.side_effect = CalledProcessError(1, 'mount')
    with self.assertRaises(TurbiniaException):
      mount_local.PreprocessMountPartition('/dev/loop0')

  @mock.patch('subprocess.check_output')
  def testGetFilesystem(self, mock_subprocess):
    """Test GetFilesystem method."""
    mock_subprocess.return_value = b'ext4'
    fstype = mount_local.GetFilesystem('/dev/loop0')
    expected_args = ['fsstat', '-t', '/dev/loop0']
    mock_subprocess.assert_called_once_with(expected_args)
    self.assertEqual(fstype, 'ext4')

    # Test too many filesystems
    mock_subprocess.reset_mock()
    mock_subprocess.return_value = b'ext4\nxfs'
    with self.assertRaises(TurbiniaException):
      mount_local.GetFilesystem('/dev/loop0')

    # Test retry loop
    mock_subprocess.reset_mock()
    mock_subprocess.side_effect = [b'', b'ext4']
    mount_local.GetFilesystem('/dev/loop0')
    self.assertEqual(fstype, 'ext4')
    self.assertEqual(mock_subprocess.call_count, 2)

  @mock.patch('subprocess.check_output')
  @mock.patch('subprocess.check_call')
  def testPostprocessDeleteLosetup(self, mock_subprocess, mock_output):
    """Test PostprocessDeleteLosetup method."""
    mock_output.return_value = b''
    mount_local.PostprocessDeleteLosetup('/dev/loop0')
    mock_subprocess.assert_called_once_with(
        ['sudo', 'losetup', '-d', '/dev/loop0'])

    # Test losetup error
    mock_subprocess.reset_mock()
    mock_subprocess.side_effect = CalledProcessError(1, 'losetup')
    with self.assertRaises(TurbiniaException):
      mount_local.PostprocessDeleteLosetup('/dev/loop0')

  @mock.patch('subprocess.check_call')
  @mock.patch('os.rmdir')
  def testPostprocessUnmountPath(self, mock_rmdir, mock_subprocess):
    """Test PostprocessUnmountPath method."""
    mount_path = '/mnt/turbinia/turbinia0ckdntz0'
    mount_local.PostprocessUnmountPath(mount_path)
    mock_subprocess.assert_called_once_with(['sudo', 'umount', mount_path])
    mock_rmdir.assert_called_once_with(mount_path)

    # Test error unmounting
    mock_subprocess.reset_mock()
    mock_rmdir.reset_mock()
    mock_subprocess.side_effect = CalledProcessError(1, 'umount')
    with self.assertRaises(TurbiniaException):
      mount_local.PostprocessUnmountPath(mount_path)

    # Test error removing mount path
    mock_subprocess.reset_mock()
    mock_subprocess.side_effect = None
    mock_rmdir.side_effect = OSError
    with self.assertRaises(TurbiniaException):
      mount_local.PostprocessUnmountPath(mount_path)


if __name__ == '__main__':
  unittest.main()
