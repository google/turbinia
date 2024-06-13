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

import os
from subprocess import CalledProcessError
from subprocess import STDOUT
import unittest

import mock

from turbinia import TurbiniaException
from turbinia.processors import mount_local


def _mock_bitlocker_returns(*args, **kwargs):
  """Mock return values."""
  if args[0] == '/dev/loop0p4':
    return False
  return True


def _mock_disk_size_returns(*args, **kwargs):
  """Mock return values."""
  if args[0][0] == 'blockdev' and args[0][2] == '/dev/loop0':
    return b'100\n'
  if args[0][0] == 'blockdev' and args[0][2] in ['test.dd', 'test2.dd']:
    raise CalledProcessError(1, 'blockdev')
  if args[0][0] == 'ls' and args[0][2] == 'test.dd':
    return b'100 test.dd\n'
  if args[0][0] == 'ls' and args[0][2] == 'test2.dd':
    raise CalledProcessError(1, 'ls')
  return ''


class MountLocalProcessorTest(unittest.TestCase):
  """Tests for mount_local processor."""

  @mock.patch('subprocess.check_output')
  @mock.patch('os.stat')
  @mock.patch('os.path.exists')
  def testGetDiskSize(self, mock_path_exists, mock_stat, mock_subprocess):
    """Test GetDiskSize method."""
    mock_path_exists.return_value = True
    source_path = '/dev/loop0'

    # Test for block device
    mock_subprocess.side_effect = _mock_disk_size_returns
    size = mount_local.GetDiskSize(source_path)
    expected_args = ['blockdev', '--getsize64', source_path]
    mock_subprocess.assert_called_once_with(expected_args, stderr=STDOUT)
    self.assertEqual(size, 100)

    # Test for image file
    source_path = 'test.dd'
    mock_stat_object = mock.MagicMock()
    mock_stat_object.st_size = 1234
    mock_stat.return_value = mock_stat_object
    size = mount_local.GetDiskSize(source_path)
    mock_stat.assert_called_with(source_path)
    self.assertEqual(size, 1234)

    # Test ls failure
    mock_stat_object.st_size = None
    source_path = 'test2.dd'
    size = mount_local.GetDiskSize(source_path)
    self.assertIsNone(size)

    # Test path doesn't exist
    mock_path_exists.return_value = False
    size = mount_local.GetDiskSize(source_path)
    self.assertIsNone(size)

  @mock.patch('turbinia.processors.mount_local.config')
  @mock.patch('tempfile.mkdtemp')
  @mock.patch('subprocess.check_call')
  @mock.patch('os.path.isdir')
  @mock.patch('os.path.exists')
  @mock.patch('os.makedirs')
  def testPreprocessAPFS(
      self, _, mock_path_exists, mock_path_isdir, mock_subprocess, mock_mkdtemp,
      mock_config):
    """Test PreprocessAPFS method."""
    mock_config.MOUNT_DIR_PREFIX = '/mnt/turbinia'
    mock_path_exists.side_effect = _mock_bitlocker_returns
    mock_mkdtemp.return_value = '/mnt/turbinia/turbinia0ckdntz0'

    current_path = os.path.abspath(os.path.dirname(__file__))
    source_path = os.path.join(
        current_path, '..', '..', 'test_data', 'apfs.raw')
    credentials = [('password', '123456')]

    # Test APFS volume
    mock_path_isdir.return_value = True
    mount_path = mount_local.PreprocessAPFS(source_path, credentials=None)
    expected_args = [
        'sudo', 'fsapfsmount', '-X', 'allow_other', source_path,
        '/mnt/turbinia/turbinia0ckdntz0'
    ]
    mock_subprocess.assert_called_once_with(expected_args)
    self.assertEqual(mount_path, '/mnt/turbinia/turbinia0ckdntz0')

    # Test encrypted APFS volume
    mock_subprocess.reset_mock()
    mount_path = mount_local.PreprocessAPFS(
        source_path, credentials=credentials)
    expected_args = [
        'sudo', 'fsapfsmount', '-p', '123456', '-X', 'allow_other', source_path,
        '/mnt/turbinia/turbinia0ckdntz0'
    ]
    mock_subprocess.assert_called_once_with(expected_args)
    self.assertEqual(mount_path, '/mnt/turbinia/turbinia0ckdntz0')

    # Test with recovery password
    mock_subprocess.reset_mock()
    credentials = [('recovery_password', '123456')]
    mount_local.PreprocessAPFS(source_path, credentials=credentials)
    expected_args = [
        'sudo', 'fsapfsmount', '-r', '123456', '-X', 'allow_other', source_path,
        '/mnt/turbinia/turbinia0ckdntz0'
    ]
    mock_subprocess.assert_called_once_with(expected_args)

    # Test if source does not exist
    with self.assertRaises(TurbiniaException):
      mount_local.PreprocessAPFS('/dev/loop0p4', credentials=credentials)

    # Test if mount path not directory
    mock_path_isdir.return_value = False
    with self.assertRaises(TurbiniaException):
      mount_local.PreprocessAPFS(source_path, credentials=credentials)
    mock_path_isdir.return_value = True

    # Test decryption failure
    mock_subprocess.reset_mock()
    mock_subprocess.side_effect = CalledProcessError(1, 'fsapfsmount')
    mount_path = mount_local.PreprocessAPFS(
        source_path, credentials=credentials)
    self.assertEqual(mount_path, None)

    # Test with unsupported credential type
    mock_subprocess.reset_mock()
    credentials = [('startup_key', 'key.BEK')]
    mount_local.PreprocessAPFS(source_path, credentials=credentials)
    mock_subprocess.assert_not_called()

  @mock.patch('turbinia.processors.mount_local.config')
  @mock.patch('tempfile.mkdtemp')
  @mock.patch('subprocess.check_call')
  @mock.patch('os.path.isdir')
  @mock.patch('os.path.exists')
  @mock.patch('os.makedirs')
  def testPreprocessEncryptedVolume(
      self, _, mock_path_exists, mock_path_isdir, mock_subprocess, mock_mkdtemp,
      mock_config):
    """Test PreprocessEncryptedVolume method."""
    mock_config.MOUNT_DIR_PREFIX = '/mnt/turbinia'
    mock_path_exists.side_effect = _mock_bitlocker_returns
    mock_mkdtemp.return_value = '/mnt/turbinia/turbinia0ckdntz0'

    current_path = os.path.abspath(os.path.dirname(__file__))
    source_path = os.path.join(current_path, '..', '..', 'test_data', 'mbr.raw')
    credentials = [('password', '123456')]

    # Test BDE
    mock_path_isdir.return_value = True
    device = mount_local.PreprocessEncryptedVolume(
        source_path, partition_offset=65536, credentials=credentials,
        encryption_type='BDE')
    expected_args = [
        'sudo', 'bdemount', '-o', '65536', '-p', '123456', '-X', 'allow_other',
        source_path, '/mnt/turbinia/turbinia0ckdntz0'
    ]
    mock_subprocess.assert_called_once_with(expected_args)
    self.assertEqual(device, '/mnt/turbinia/turbinia0ckdntz0/bde1')

    # Test LUKSDE
    mock_subprocess.reset_mock()
    mock_path_isdir.return_value = True
    device = mount_local.PreprocessEncryptedVolume(
        source_path, partition_offset=65536, credentials=credentials,
        encryption_type='LUKSDE')
    expected_args = [
        'sudo', 'luksdemount', '-o', '65536', '-p', '123456', '-X',
        'allow_other', source_path, '/mnt/turbinia/turbinia0ckdntz0'
    ]
    mock_subprocess.assert_called_once_with(expected_args)
    self.assertEqual(device, '/mnt/turbinia/turbinia0ckdntz0/luksde1')

    # Test with recovery password
    mock_subprocess.reset_mock()
    credentials = [('recovery_password', '123456')]
    mount_local.PreprocessEncryptedVolume(
        source_path, partition_offset=65536, credentials=credentials,
        encryption_type='BDE')
    expected_args = [
        'sudo', 'bdemount', '-o', '65536', '-r', '123456', '-X', 'allow_other',
        source_path, '/mnt/turbinia/turbinia0ckdntz0'
    ]
    mock_subprocess.assert_called_once_with(expected_args)

    # Test if source does not exist
    with self.assertRaises(TurbiniaException):
      mount_local.PreprocessEncryptedVolume(
          '/dev/loop0p4', partition_offset=65536, credentials=credentials,
          encryption_type='BDE')

    # Test if mount path not directory
    mock_path_isdir.return_value = False
    with self.assertRaises(TurbiniaException):
      mount_local.PreprocessEncryptedVolume(
          source_path, partition_offset=65536, credentials=credentials,
          encryption_type='BDE')
    mock_path_isdir.return_value = True

    # Test decryption failure
    mock_subprocess.reset_mock()
    mock_subprocess.side_effect = CalledProcessError(1, 'bdemount')
    device = mount_local.PreprocessEncryptedVolume(
        source_path, partition_offset=65536, credentials=credentials,
        encryption_type='BDE')
    self.assertEqual(device, None)

    # Test with unsupported credential type
    mock_subprocess.reset_mock()
    credentials = [('startup_key', 'key.BEK')]
    mount_local.PreprocessEncryptedVolume(
        source_path, partition_offset=65536, credentials=credentials,
        encryption_type='BDE')
    mock_subprocess.assert_not_called()

  @mock.patch('turbinia.processors.mount_local.config')
  @mock.patch('subprocess.check_output')
  def testPreprocessLosetup(self, mock_subprocess, mock_config):
    """Test PreprocessLosetup method."""
    current_path = os.path.abspath(os.path.dirname(__file__))
    source_path = os.path.join(current_path, '..', '..', 'test_data', 'mbr.raw')
    mock_config.RESOURCE_FILE_LOCK = '/tmp/turbinia_resource.lock'
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
  @mock.patch('subprocess.check_call')
  @mock.patch('os.path.isdir')
  @mock.patch('os.path.exists')
  @mock.patch('os.makedirs')
  def testPreprocessMountEwfDisk(
      self, _, mock_path_exists, mock_path_isdir, mock_subprocess, mock_mkdtemp,
      mock_config):
    """Test PreprocessMountEwfDisk method."""
    mock_config.MOUNT_DIR_PREFIX = '/mnt/turbinia'
    mock_path_exists.side_effect = _mock_bitlocker_returns
    mock_mkdtemp.return_value = '/mnt/turbinia/turbinia0ckdntz0'

    current_path = os.path.abspath(os.path.dirname(__file__))
    source_path = os.path.join(
        current_path, '..', '..', 'test_data', 'ext2.E01')

    # Test ewfmount
    mock_path_isdir.return_value = True
    device = mount_local.PreprocessMountEwfDisk(source_path)
    expected_args = [
        'sudo', 'ewfmount', '-X', 'allow_other', source_path,
        '/mnt/turbinia/turbinia0ckdntz0'
    ]
    mock_subprocess.assert_called_once_with(expected_args)
    self.assertEqual(device, '/mnt/turbinia/turbinia0ckdntz0')

    # Test if source does not exist
    with self.assertRaises(TurbiniaException):
      mount_local.PreprocessMountEwfDisk('/dev/loop0p4')

    # Test if mount path not directory
    mock_path_isdir.return_value = False
    with self.assertRaises(TurbiniaException):
      mount_local.PreprocessMountEwfDisk(source_path)
    mock_path_isdir.return_value = True

    # Test ewfmount failure
    mock_subprocess.reset_mock()
    mock_subprocess.side_effect = CalledProcessError(1, 'ewfmount')
    with self.assertRaises(TurbiniaException):
      device = mount_local.PreprocessMountEwfDisk(source_path)

  @mock.patch('subprocess.check_output')
  @mock.patch('subprocess.check_call')
  def testPreprocessLVM(self, mock_subprocess, mock_output):
    """Test PreprocessLosetup method on LVM."""
    source_path = os.path.join('/dev/loop0')
    lv_uuid = 'RI0pgm-rdy4-XxcL-5eoK-Easc-fgPq-CWaEJb'
    mock_output.return_value = (
        '  /dev/test_volume_group/test_logical_volume1:test_volume_group:3:0:-1:'
        '0:8192:1:-1:0:-1:-1:-1\n')
    device = mount_local.PreprocessLosetup(source_path, lv_uuid=lv_uuid)
    expected_args = [
        'sudo', 'lvdisplay', '--colon', '--select', f'lv_uuid={lv_uuid:s}'
    ]
    mock_output.assert_called_once_with(expected_args, universal_newlines=True)
    mock_subprocess.assert_called_once_with(
        ['sudo', 'vgchange', '-a', 'y', 'test_volume_group'])
    self.assertEqual(device, '/dev/test_volume_group/test_logical_volume1')

    # Test vgchange error
    mock_subprocess.reset_mock()
    mock_subprocess.side_effect = CalledProcessError(1, 'vgchange')
    with self.assertRaises(TurbiniaException):
      mount_local.PreprocessLosetup(source_path, lv_uuid=lv_uuid)

    # Test lvdisplay failure
    mock_output.side_effect = CalledProcessError(1, 'lvdisplay')
    with self.assertRaises(TurbiniaException):
      mount_local.PreprocessLosetup(source_path, lv_uuid=lv_uuid)

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
    mock_path_exists.side_effect = _mock_bitlocker_returns
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
  @mock.patch('subprocess.check_call')
  @mock.patch('os.path.isdir')
  @mock.patch('os.path.exists')
  @mock.patch('os.makedirs')
  def testPreprocessMountPartition(
      self, _, mock_path_exists, mock_path_isdir, mock_subprocess, mock_mkdtemp,
      mock_config):
    """Test PreprocessMountPartition method."""
    mock_config.MOUNT_DIR_PREFIX = '/mnt/turbinia'
    mock_path_exists.side_effect = _mock_bitlocker_returns
    mock_mkdtemp.return_value = '/mnt/turbinia/turbinia0ckdntz0'

    # Test partition path doesn't exist
    with self.assertRaises(TurbiniaException):
      mount_local.PreprocessMountPartition('/dev/loop0p4', 'EXT')

    # Test mount prefix is not directory
    mock_path_isdir.return_value = False
    with self.assertRaises(TurbiniaException):
      mount_local.PreprocessMountPartition('/dev/loop0', 'EXT')
    mock_path_isdir.return_value = True

    # Test ext4
    mount_path = mount_local.PreprocessMountPartition('/dev/loop0', 'EXT')
    expected_args = [
        'sudo', 'mount', '-o', 'ro', '-o', 'noload', '/dev/loop0',
        '/mnt/turbinia/turbinia0ckdntz0'
    ]
    mock_subprocess.assert_called_once_with(expected_args)
    self.assertEqual(mount_path, '/mnt/turbinia/turbinia0ckdntz0')

    # Test xfs
    mock_subprocess.reset_mock()
    mount_path = mount_local.PreprocessMountPartition('/dev/loop0', 'XFS')
    expected_args = [
        'sudo', 'mount', '-o', 'ro', '-o', 'norecovery', '-o', 'nouuid',
        '/dev/loop0', '/mnt/turbinia/turbinia0ckdntz0'
    ]
    mock_subprocess.assert_called_once_with(expected_args)
    self.assertEqual(mount_path, '/mnt/turbinia/turbinia0ckdntz0')

    # Test mount failure
    mock_subprocess.reset_mock()
    mock_subprocess.side_effect = CalledProcessError(1, 'mount')
    with self.assertRaises(TurbiniaException):
      mount_local.PreprocessMountPartition('/dev/loop0', 'EXT')

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

  @mock.patch('turbinia.processors.mount_local.config')
  @mock.patch('subprocess.check_output')
  @mock.patch('subprocess.check_call')
  def testPostprocessDeleteLosetup(
      self, mock_subprocess, mock_output, mock_config):
    """Test PostprocessDeleteLosetup method."""
    mock_config.RESOURCE_FILE_LOCK = '/tmp/turbinia_resource.lock'
    mock_output.return_value = ''
    mount_local.PostprocessDeleteLosetup('/dev/loop0')
    mock_subprocess.assert_called_once_with(
        ['sudo', 'losetup', '-d', '/dev/loop0'])

    # Test losetup error
    mock_subprocess.reset_mock()
    mock_subprocess.side_effect = CalledProcessError(1, 'losetup')
    with self.assertRaises(TurbiniaException):
      mount_local.PostprocessDeleteLosetup('/dev/loop0')

  @mock.patch('subprocess.check_output')
  @mock.patch('subprocess.check_call')
  def testPostprocessDeleteLVM(self, mock_subprocess, mock_output):
    """Test PostprocessDeleteLosetup method on LVM."""
    lv_uuid = 'RI0pgm-rdy4-XxcL-5eoK-Easc-fgPq-CWaEJb'
    mock_output.return_value = (
        '  /dev/test_volume_group/test_logical_volume1:test_volume_group:3:0:-1:'
        '0:8192:1:-1:0:-1:-1:-1\n')
    mount_local.PostprocessDeleteLosetup(None, lv_uuid=lv_uuid)
    expected_args = [
        'sudo', 'lvdisplay', '--colon', '--select', f'lv_uuid={lv_uuid:s}'
    ]
    mock_output.assert_called_once_with(expected_args, universal_newlines=True)
    mock_subprocess.assert_called_once_with(
        ['sudo', 'vgchange', '-a', 'n', 'test_volume_group'])

    # Test vgchange error
    mock_subprocess.reset_mock()
    mock_subprocess.side_effect = CalledProcessError(1, 'vgchange')
    with self.assertRaises(TurbiniaException):
      mount_local.PostprocessDeleteLosetup(None, lv_uuid=lv_uuid)

    # Test lvdisplay error
    mock_output.reset_mock()
    mock_output.side_effect = CalledProcessError(1, 'lvdisplay')
    with self.assertRaises(TurbiniaException):
      mount_local.PostprocessDeleteLosetup(None, lv_uuid=lv_uuid)

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
