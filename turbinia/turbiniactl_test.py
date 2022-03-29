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
import tempfile

from unittest import mock
from libcloudforensics.providers.gcp.internal import compute
from turbinia import config
from turbinia import TurbiniaException
from turbinia import turbiniactl
from turbinia.lib import recipe_helpers
from turbinia.message import TurbiniaRequest
from turbinia.processors import archive


class FakeEvidence():
  """Class to represent a fake Evidence object. """

  def __init__(
      self, name='My Evidence', type=None, source_path=None, cloud_only=False,
      copyable=False, disk_name=None, project=None, zone=None):
    self.source = 'testSource'
    self.name = name
    self.type = type
    self.source_path = source_path
    self.cloud_only = cloud_only
    self.copyable = copyable
    self.type = type
    self.project = project
    self.disk_name = disk_name
    self.zone = zone

  def set_parent(self, _):
    """Set evidence parent."""
    return


class TestTurbiniactl(unittest.TestCase):
  """ Test Turbiniactl."""

  @mock.patch('turbinia.output_manager.OutputManager.setup')
  @mock.patch('turbinia.output_manager.OutputManager.save_evidence')
  # pylint: disable=arguments-differ
  def setUp(self, _, __):
    super(TestTurbiniactl, self).setUp()
    config.TASK_MANAGER = 'celery'
    self.output_manager = mock.MagicMock()
    self.base_dir = tempfile.mkdtemp()
    self.source_path = tempfile.mkstemp(dir=self.base_dir)[1]

  @mock.patch('turbinia.client.get_turbinia_client')
  @mock.patch('turbinia.evidence.RawDisk')
  def testRawDiskEvidence(self, mockEvidence, mockClient):
    """Test RawDisk evidence."""
    mockClient.create_request.return_value = TurbiniaRequest()
    args = argparse.Namespace(
        request_id=None, command='rawdisk', force_evidence=False,
        decryption_keys=None, recipe=None, recipe_path=None, dump_json=None,
        debug_tasks=None, jobs_denylist=None, jobs_allowlist=None,
        run_local=False, wait=False)
    mockEvidence.return_value = FakeEvidence(
        type='rawdisk', source_path=self.source_path)
    config.SHARED_FILESYSTEM = True
    turbiniactl.process_evidence(
        name='My Evidence', source_path='/tmp/foo.img', args=args,
        source='case', client=mockClient, group_id='FakeGroupID')
    mockEvidence.assert_called_with(
        name='My Evidence', source_path='/tmp/foo.img', source='case')

  @mock.patch('turbinia.client.get_turbinia_client')
  @mock.patch('turbinia.evidence.CompressedDirectory')
  @mock.patch('turbinia.evidence.Directory')
  def testDirectoryDiskEvidence(
      self, mockDirectory, mockCompressedEvidence, mockClient):
    """Test directory evidence."""
    mockClient.create_request.return_value = TurbiniaRequest()
    args = argparse.Namespace(
        request_id=None, command='directory', force_evidence=False,
        decryption_keys=None, recipe=None, recipe_path=None, dump_json=None,
        debug_tasks=None, jobs_denylist=None, jobs_allowlist=None,
        run_local=False, wait=False)
    # Test not shared filesystem
    archive.CompressDirectory = mock.MagicMock()
    config.SHARED_FILESYSTEM = False
    mockCompressedEvidence.return_value = FakeEvidence(
        type='compresseddirectory', source_path=self.source_path,
        cloud_only=True)
    mockClient.send_request = mock.MagicMock()
    turbiniactl.process_evidence(
        name='My Evidence', source_path=self.source_path, args=args,
        source='case', client=mockClient, group_id='FakeGroupID')
    self.assertTrue(archive.CompressDirectory.called)
    mockCompressedEvidence.assert_called_with(
        name='My Evidence', source_path=mock.ANY, source='case')
    # Test Directory evidence for shared filesystem
    mockDirectory.return_value = FakeEvidence(
        type='directory', source_path=self.source_path)
    mockDirectory.cloud_only = False
    config.SHARED_FILESYSTEM = True
    turbiniactl.process_evidence(
        name='My Evidence', source_path=self.source_path, args=args,
        source='case', client=mockClient, group_id='FakeGroupID')
    mockDirectory.assert_called_with(
        name='My Evidence', source_path=mock.ANY, source='case')

  @mock.patch('turbinia.client.get_turbinia_client')
  @mock.patch('turbinia.evidence.CompressedDirectory')
  def testCompressedDirectory(self, mockEvidence, mockClient):
    """Test compressed directory evidence"""
    mockClient.create_request.return_value = TurbiniaRequest()
    args = argparse.Namespace(
        request_id=None, command='compresseddirectory', force_evidence=False,
        decryption_keys=None, recipe=None, recipe_path=None, dump_json=None,
        debug_tasks=None, jobs_denylist=None, jobs_allowlist=None,
        run_local=False, wait=False)
    archive.ValidateTarFile = mock.MagicMock()
    mockEvidence.return_value = FakeEvidence(
        type='compresseddirectory', source_path=self.source_path,
        cloud_only=True)
    mockClient.send_request = mock.MagicMock()
    turbiniactl.process_evidence(
        name='My Evidence', source_path=self.source_path, args=args,
        source='case', client=mockClient, group_id='FakeGroupID')
    self.assertTrue(archive.ValidateTarFile.called)
    mockEvidence.assert_called_with(
        name='My Evidence', source_path=mock.ANY, source='case')

  @mock.patch('turbinia.client.get_turbinia_client')
  @mock.patch('turbinia.evidence.GoogleCloudDisk')
  def testCloudDisk(self, mockEvidence, mockClient):
    """Test Google Cloud Disk evidence."""
    mockClient.create_request.return_value = TurbiniaRequest()
    args = argparse.Namespace(
        request_id=None, command='googleclouddisk', force_evidence=False,
        decryption_keys=None, recipe=None, recipe_path=None, dump_json=None,
        debug_tasks=None, jobs_denylist=None, jobs_allowlist=None,
        run_local=False, wait=False)
    mockEvidence.return_value = FakeEvidence(
        type='googleclouddisk', project='testProject', disk_name='testDisk',
        cloud_only=True)
    turbiniactl.process_evidence(
        name='My Evidence', disk_name='testDisk', zone='testZone',
        project='testProject', args=args, source='case', client=mockClient,
        group_id='FakeGroupID')
    mockEvidence.assert_called_with(
        name='My Evidence', disk_name='testDisk', project='testProject',
        source='case', zone='testZone')

  @mock.patch('turbinia.output_manager.OutputManager.setup')
  @mock.patch('turbinia.output_manager.OutputManager.save_evidence')
  @mock.patch('turbinia.client.get_turbinia_client')
  @mock.patch('turbinia.evidence.GoogleCloudDiskRawEmbedded')
  @mock.patch('turbinia.evidence.GoogleCloudDisk')
  def testCloudEmbedded(
      self, mockCloudEvidence, mockEmbeddedEvidence, mockClient, _, __):
    """Test Google Cloud Disk Embedded evidence."""
    mockClient.create_request.return_value = TurbiniaRequest()
    args = argparse.Namespace(
        request_id=None, command='googleclouddiskembedded',
        force_evidence=False, decryption_keys=None, recipe=None,
        recipe_path=None, dump_json=None, debug_tasks=None, jobs_denylist=None,
        jobs_allowlist=None, run_local=False, wait=False)
    mockCloudEvidence.return_value = FakeEvidence(
        type='googleclouddisk', project='testProject', disk_name='testDisk',
        cloud_only=True)
    mockEmbeddedEvidence.return_value = FakeEvidence(
        type='googleclouddiskembedded', project='testProject',
        disk_name='testDisk', cloud_only=True)
    mockClient.send_request = mock.MagicMock()
    mockEmbeddedEvidence.set_parent = mock.MagicMock()
    turbiniactl.process_evidence(
        name='My Evidence', disk_name='testDisk', zone='testZone',
        project='testProject', args=args, source='case', client=mockClient,
        group_id='FakeGroupID', mount_partition='testMount')
    mockCloudEvidence.assert_called_with(
        name='My Evidence', disk_name='testDisk', project='testProject',
        source='case', zone='testZone', mount_partition='testMount')
    mockEmbeddedEvidence.assert_called_with(
        name='My Evidence', disk_name='testDisk', project='testProject',
        zone='testZone', embedded_path=mock.ANY)
    self.assertTrue(mockEmbeddedEvidence.called)

  @mock.patch('turbinia.client.get_turbinia_client')
  @mock.patch('turbinia.evidence.ChromiumProfile')
  def testHindsight(self, mockEvidence, mockClient):
    """Test hindsight evidence"""
    mockClient.create_request.return_value = TurbiniaRequest()
    args = argparse.Namespace(
        request_id=None, command='hindsight', force_evidence=False,
        decryption_keys=None, recipe=None, recipe_path=None, dump_json=None,
        debug_tasks=None, jobs_denylist=None, jobs_allowlist=None,
        run_local=False, wait=False)
    with self.assertRaisesRegex(TurbiniaException, 'Invalid output format.'):
      turbiniactl.process_evidence(
          name='My Evidence', source_path=self.source_path, args=args,
          client=mockClient, group_id='FakeGroupID', format='invalid')

    with self.assertRaisesRegex(TurbiniaException, 'Browser type'):
      turbiniactl.process_evidence(
          name='My Evidence', source_path=self.source_path, args=args,
          client=mockClient, group_id='FakeGroupID', format='sqlite',
          browser_type='firefox')

    mockEvidence.return_value = FakeEvidence(
        type='chromiumProfile', source_path=self.source_path)
    turbiniactl.process_evidence(
        name='My Evidence', source_path=self.source_path, args=args,
        client=mockClient, group_id='FakeGroupID', format='sqlite',
        browser_type='Chrome')
    mockEvidence.assert_called_with(
        name='My Evidence', output_format='sqlite', browser_type='Chrome',
        source_path=mock.ANY)

  @mock.patch('turbinia.client.get_turbinia_client')
  @mock.patch('turbinia.evidence.RawMemory')
  def testRawMemory(self, mockEvidence, mockClient):
    """Test raw memory evidence"""
    mockClient.create_request.return_value = TurbiniaRequest()
    args = argparse.Namespace(
        request_id=None, command='rawmemory', force_evidence=False,
        decryption_keys=None, recipe=None, recipe_path=None, dump_json=None,
        debug_tasks=None, jobs_denylist=None, jobs_allowlist=None,
        run_local=False, wait=False, module_list=['mod1', 'mod2'])
    mockEvidence.return_value = FakeEvidence(
        type='rawmemory', source_path=self.source_path)
    turbiniactl.process_evidence(
        name='My Evidence', source_path=self.source_path, args=args,
        client=mockClient, group_id='FakeGroupID', profile='testProfile')

    mockEvidence.assert_called_with(
        name='My Evidence', source_path=mock.ANY, profile='testProfile',
        module_list=['mod1', 'mod2'])

  @mock.patch('turbinia.client.get_turbinia_client')
  def testUnequalDirectoryArgs(self, _):
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

  @mock.patch('turbinia.client.get_turbinia_client')
  def testUnequalRawdiskArgs(self, mockClient):
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

  @mock.patch('turbinia.client.get_turbinia_client')
  def testUnequalCompresseddirectoryArgs(self, _):
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
  @mock.patch('argparse.ArgumentParser.parse_args')
  def testUnequalCloudDiskArgs(self, mockParser, mock_copyDisk, _):
    """Test unequal number of args for cloud disk evidence type."""
    config.SHARED_FILESYSTEM = False
    config.TASK_MANAGER = 'PSQ'
    mockArgs = argparse.Namespace(
        all_fields=False, command='googleclouddisk', config_file=None,
        copy_only=False, debug=False, debug_tasks=False, decryption_keys=[],
        disk_name=['disk1', 'disk2', 'disk3'], dump_json=False, embedded_path=[
            'path1', 'path2', 'path3'
        ], filter_patterns_file=None, force_evidence=False, jobs_allowlist=[],
        jobs_denylist=[], log_file=None, mount_partition=None,
        name=None, output_dir=None, poll_interval=60, project=[
            'proj1', 'proj2', 'proj3'
        ], quiet=False, recipe=None, recipe_path=None, request_id=None,
        server=False, skip_recipe_validation=False, source=[None], verbose=True,
        wait=False, yara_rules_file=None, zone=['zone1', 'zone2'])
    mockParser.return_value = mockArgs

    # Fail when zones dont match
    self.assertRaises(
        TurbiniaException, turbiniactl.process_args, [
            'googleclouddisk', '--disk_name', 'disk1,disk2,disk3', '--zone',
            'zone1,zone2', '--project', 'proj1,proj2,proj3'
        ])

    # Fail when projects don't match
    mockArgs.zone = ['zone1', 'zone2', 'zone3']
    mockArgs.project = ['proj1', 'proj2']
    mockParser.return_value = mockArgs
    self.assertRaises(
        TurbiniaException, turbiniactl.process_args, [
            'googleclouddisk', '--disk_name', 'disk1,disk2,disk3', '--zone',
            'zone1,zone2,zone3', '--project', 'proj1,proj2'
        ])

    #Fail when names dont match
    mockArgs.project = ['proj1', 'proj2', 'proj3']
    mockArgs.name = ['name1', 'name2']
    mockParser.return_value = mockArgs
    self.assertRaises(
        TurbiniaException, turbiniactl.process_args, [
            'googleclouddisk', '--disk_name', 'disk1,disk2,disk3', '--zone',
            'zone1,zone2,zone3', '--project', 'proj1,proj2,proj3', '--name',
            'name1,name2'
        ])
    mockArgs.name = ['name1', 'name2', 'name3']
    mockArgs.source = ['source1', 'source2']
    self.assertRaises(
        TurbiniaException, turbiniactl.process_args, [
            'googleclouddisk', '--disk_name', 'disk1,disk2,disk3', '--zone',
            'zone1,zone2,zone3', '--project', 'proj1,proj2,proj3', '--source',
            'source1,source2'
        ])

    mockArgs.source = ['source1', 'source2', 'source3']
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
    config.SHARED_FILESYSTEM = False
    config.TASK_MANAGER = 'PSQ'
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
    turbiniactl.process_evidence = mock.MagicMock(return_value=None)
    mock_copyDisk.return_value = compute.GoogleComputeDisk(
        'fake-proj', 'fake-zone', 'fake-disk-copy')
    turbiniactl.process_args([
        'googleclouddiskembedded', '--disk_name', 'disk1,disk2,disk3', '--zone',
        'zone1,zone2,zone3', '--project', 'proj1,proj2,proj3',
        '--embedded_path', 'path1,path2,path3'
    ])
    self.assertTrue(turbiniactl.process_evidence.called)

    # Raise error when running locally
    config.SHARED_FILESYSTEM = True
    with self.assertRaisesRegex(TurbiniaException, 'Cloud only'):
      turbiniactl.process_args([
          'googleclouddiskembedded', '--disk_name', 'disk1,disk2,disk3',
          '--zone', 'zone1,zone2,zone3', '--project', 'proj1,proj2,proj3',
          '--embedded_path', 'path1,path2,path3'
      ])

  @mock.patch('turbinia.client.get_turbinia_client')
  def testUnequalRawMemoryArgs(self, _):
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

  @mock.patch('turbinia.client.get_turbinia_client')
  def testUnequalHindsightArgs(self, _):
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

  @mock.patch('turbinia.client.get_turbinia_client')
  def testTurbiniaClientRequest(self, mockClient):
    """Test Turbinia client request creation."""
    config.TASK_MANAGER = 'celery'
    mockClient.create_request = mock.MagicMock()
    mockClient.create_request.return_value = TurbiniaRequest(
        recipe=recipe_helpers.DEFAULT_RECIPE)
    test_request = mockClient.create_request()
    self.assertIsNotNone(test_request)
    test_default_recipe = recipe_helpers.DEFAULT_RECIPE
    self.assertEqual(test_request.recipe, test_default_recipe)