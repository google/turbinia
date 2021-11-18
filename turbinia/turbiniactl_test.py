# -*- coding: utf-8 -*-
# Copyright 2019 Google Inc.
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
"""Tests for Turbinia task_manager module."""

from __future__ import unicode_literals
import argparse

import unittest

from turbinia import config
from turbinia import TurbiniaException
from turbinia import turbiniactl
from turbinia.jobs import manager as jobs_manager
from turbinia.jobs import plaso
from turbinia.jobs import strings
from turbinia.workers.workers_test import TestTurbiniaTaskBase
from unittest import mock
from unittest.mock import patch
from libcloudforensics.providers.gcp.internal import compute


class TestTurbiniactl(unittest.TestCase):
  """ Test Turbiniactl."""

  def setUp(self):
    config.TASK_MANAGER = 'CELERY'

  def testUnequalDirectoryArgs(self):
    """Test unequal number of args for directory evidence type."""
    self.assertRaises(
        TurbiniaException, turbiniactl.process_args, [
            'directory', '--source_path', 'img1,img2', '--source',
            'source,source2,source3'
        ])
    self.assertRaises(
        TurbiniaException, turbiniactl.process_args, [
            'directory', '--source_path', 'img1,img2', '--name',
            'name1,name2,name3'
        ])

    turbiniactl.process_evidence = mock.MagicMock(return_value=None)
    turbiniactl.process_args([
        'directory', '--source_path', 'img1,img2', '--source', 'source,source2'
    ])
    self.assertTrue(turbiniactl.process_evidence.called)

  def testUnequalRawdiskArgs(self):
    """Test unequal number of args for rawdisk evidence type."""
    self.assertRaises(
        TurbiniaException, turbiniactl.process_args, [
            'rawdisk', '--source_path', 'img1,img2', '--source',
            'source,source2,source3'
        ])
    self.assertRaises(
        TurbiniaException, turbiniactl.process_args, [
            'rawdisk', '--source_path', 'img1,img2', '--name',
            'name1,name2,name3'
        ])
    turbiniactl.process_evidence = mock.MagicMock(return_value=None)
    turbiniactl.process_args(
        ['rawdisk', '--source_path', 'img1,img2', '--name', 'name1,name2'])
    self.assertTrue(turbiniactl.process_evidence.called)

  def testUnequalCompresseddirectoryArgs(self):
    """Test unequal number of args for compresseddirectory evidence type."""
    self.assertRaises(
        TurbiniaException, turbiniactl.process_args, [
            'compresseddirectory', '--source_path', 'img1,img2,img3',
            '--source', 'source1,source2'
        ])

    self.assertRaises(
        TurbiniaException, turbiniactl.process_args, [
            'compresseddirectory', '--source_path', 'img1,img2', '--name',
            'name1,name2,name3'
        ])

    turbiniactl.process_evidence = mock.MagicMock(return_value=None)
    turbiniactl.process_args([
        'compresseddirectory', '--source_path', 'img1,img2', '--name',
        'name1,name2'
    ])
    self.assertTrue(turbiniactl.process_evidence.called)

  @mock.patch('turbinia.client.get_turbinia_client')
  @mock.patch('libcloudforensics.providers.gcp.forensics.CreateDiskCopy')
  def testUnequalCloudDiskArgs(self, mock_copyDisk, _):
    """Test unequal number of args for cloud disk evidence type."""
    self.assertRaises(
        TurbiniaException, turbiniactl.process_args, [
            'googleclouddisk', '--disk_name', 'disk1,disk2,disk3', '--zone',
            'zone1,zone2', '--project', 'proj1,proj2,proj3'
        ])

    self.assertRaises(
        TurbiniaException, turbiniactl.process_args, [
            'googleclouddisk', '--disk_name', 'disk1,disk2,disk3', '--zone',
            'zone1,zone2,zone3', '--project', 'proj1,proj2'
        ])

    self.assertRaises(
        TurbiniaException, turbiniactl.process_args, [
            'googleclouddisk', '--disk_name', 'disk1,disk2,disk3', '--zone',
            'zone1,zone2,zone3', '--project', 'proj1,proj2,proj3', '--name',
            'name1,name2'
        ])

    self.assertRaises(
        TurbiniaException, turbiniactl.process_args, [
            'googleclouddisk', '--disk_name', 'disk1,disk2,disk3', '--zone',
            'zone1,zone2,zone3', '--project', 'proj1,proj2,proj3', '--source',
            'source1,source2'
        ])

    config.TASK_MANAGER = 'PSQ'
    turbiniactl.process_evidence = mock.MagicMock(return_value=None)
    mock_copyDisk.return_value = compute.GoogleComputeDisk(
        'fake-proj', 'fake-zone', 'fake-disk-copy')
    turbiniactl.process_args([
        'googleclouddisk', '--disk_name', 'disk1,disk2,disk3', '--zone',
        'zone1,zone2,zone3', '--project', 'proj1,proj2,proj3'
    ])
    self.assertTrue(turbiniactl.process_evidence.called)

  @mock.patch('turbinia.client.get_turbinia_client')
  @mock.patch('libcloudforensics.providers.gcp.forensics.CreateDiskCopy')
  def testUnequalCloudDiskEmbeddedArgs(self, mock_copyDisk, _):
    """Test unequal number of args for cloud embedded disk evidence type."""
    # Fail when zones don't match
    self.assertRaises(
        TurbiniaException, turbiniactl.process_args, [
            'googleclouddiskembedded', '--disk_name', 'disk1,disk2,disk3',
            '--zone', 'zone1,zone2', '--project', 'proj1,proj2,proj3',
            '--embedded_path', 'path1,path2,path3'
        ])

    # Fail when embedded path don't match
    self.assertRaises(
        TurbiniaException, turbiniactl.process_args, [
            'googleclouddiskembedded', '--disk_name', 'disk1,disk2,disk3',
            '--zone', 'zone1,zone2,zone3', '--project', 'proj1,proj2,proj3',
            '--embedded_path', 'path1,path2'
        ])

    # Fail when name don't match
    self.assertRaises(
        TurbiniaException, turbiniactl.process_args, [
            'googleclouddiskembedded', '--disk_name', 'disk1,disk2', '--zone',
            'zone1,zone2,zone3', '--project', 'proj1,proj2,proj3', '--name',
            'name1,name2', '--embedded_path', 'path1,path2,path3'
        ])
    # Fail when mount source don't match
    self.assertRaises(
        TurbiniaException, turbiniactl.process_args, [
            'googleclouddiskembedded', '--disk_name', 'disk1,disk2,disk3',
            '--zone', 'zone1,zone2,zone3', '--project', 'proj1,proj2,proj3',
            '--source', 'source1,source2', '--embedded_path',
            'path1,path2,path3'
        ])

    # Fail when project don't match
    self.assertRaises(
        TurbiniaException, turbiniactl.process_args, [
            'googleclouddiskembedded', '--disk_name', 'disk1,disk2,disk3',
            '--zone', 'zone1,zone2,zone3', '--project', 'proj1,proj2',
            '--source', 'source1,source2', '--embedded_path',
            'path1,path2,path3'
        ])

    # Pass when all the args match
    config.TASK_MANAGER = 'PSQ'
    turbiniactl.process_evidence = mock.MagicMock(return_value=None)
    mock_copyDisk.return_value = compute.GoogleComputeDisk(
        'fake-proj', 'fake-zone', 'fake-disk-copy')
    turbiniactl.process_args([
        'googleclouddiskembedded', '--disk_name', 'disk1,disk2,disk3', '--zone',
        'zone1,zone2,zone3', '--project', 'proj1,proj2,proj3',
        '--embedded_path', 'path1,path2,path3'
    ])
    self.assertTrue(turbiniactl.process_evidence.called)

  def testUnequalRawMemoryArgs(self):
    """Test unequal number of args for rawmemory evidence type."""
    self.assertRaises(
        TurbiniaException, turbiniactl.process_args, [
            'rawmemory', '--source_path', 'disk1,disk2,disk3', '--profile',
            'prof1,prof2,prof3,prof4', '--module_list', 'mock'
        ])
    self.assertRaises(
        TurbiniaException, turbiniactl.process_args, [
            'rawmemory', '--source_path', 'disk1,disk2,disk3', '--profile',
            'prof1,prof2,prof3', '--module_list', 'mock', '--name',
            'name1,name2'
        ])

    turbiniactl.process_evidence = mock.MagicMock(return_value=None)
    turbiniactl.process_args([
        'rawmemory', '--source_path', 'disk1,disk2,disk3', '--profile',
        'prof1,prof2,prof3', '--module_list', 'mock'
    ])
    self.assertTrue(turbiniactl.process_evidence.called)

  def testUnequalHindsightArgs(self):
    """Test unequal number of args for hindsight evidence type."""
    self.assertRaises(
        TurbiniaException, turbiniactl.process_args, [
            'hindsight', '--source_path', 'disk1,disk2,disk3', '--format',
            'prof1,prof2,prof3', '--name', 'name1,name2'
        ])
    self.assertRaises(
        TurbiniaException, turbiniactl.process_args, [
            'hindsight', '--source_path', 'disk1,disk2,disk3', '--format',
            'sqlite,sqlite,sqlite,sqlite'
        ])
    self.assertRaises(
        TurbiniaException, turbiniactl.process_args, [
            'hindsight', '--source_path', 'disk1,disk2,disk3', '--format',
            'sqlite,sqlite,sqlite', '--browser_type', 'type1,type2'
        ])

    turbiniactl.process_evidence = mock.MagicMock(return_value=None)
    turbiniactl.process_args(
        ['hindsight', '--source_path', 'disk1,disk2,disk3'])
    self.assertTrue(turbiniactl.process_evidence.called)
