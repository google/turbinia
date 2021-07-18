# -*- coding: utf-8 -*-
# Copyright 2018 Google Inc.
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
"""Tests for Turbinia worker module."""

from __future__ import unicode_literals

import unittest
import os
import shutil
import tempfile

import mock

from turbinia import config
from turbinia.worker import TurbiniaPsqWorker
from turbinia.worker import check_system_dependencies
from turbinia.worker import check_docker_dependencies
from turbinia.jobs import manager
from turbinia.jobs import manager_test
from turbinia import TurbiniaException


class TestTurbiniaPsqWorker(unittest.TestCase):
  """Test Turbinia PSQ Worker class."""

  def setUp(self):
    self.tmp_dir = tempfile.mkdtemp(prefix='turbinia-test')
    config.LoadConfig()
    config.OUTPUT_DIR = self.tmp_dir
    config.MOUNT_DIR_PREFIX = self.tmp_dir
    config.ParseDependencies = mock.MagicMock(return_value={})
    self.saved_jobs = manager.JobsManager._job_classes

  def tearDown(self):
    manager.JobsManager._job_classes = self.saved_jobs
    if 'turbinia-test' in self.tmp_dir:
      shutil.rmtree(self.tmp_dir)

  @mock.patch('turbinia.worker.pubsub')
  @mock.patch('turbinia.worker.datastore.Client')
  @mock.patch('turbinia.worker.psq.Worker')
  @mock.patch('turbinia.lib.docker_manager.DockerManager')
  def testTurbiniaPsqWorkerInit(self, _, __, ___, ____):
    """Basic test for PSQ worker."""
    worker = TurbiniaPsqWorker([], [])
    self.assertTrue(hasattr(worker, 'worker'))

  @mock.patch('turbinia.worker.pubsub')
  @mock.patch('turbinia.worker.datastore.Client')
  @mock.patch('turbinia.worker.psq.Worker')
  @mock.patch('turbinia.lib.docker_manager.DockerManager')
  def testTurbiniaWorkerNoDir(self, _, __, ___, ____):
    """Test that OUTPUT_DIR path is created."""
    config.OUTPUT_DIR = os.path.join(self.tmp_dir, 'no_such_dir')
    TurbiniaPsqWorker([], [])
    self.assertTrue(os.path.exists(config.OUTPUT_DIR))

  @mock.patch('turbinia.worker.pubsub')
  @mock.patch('turbinia.worker.datastore.Client')
  @mock.patch('turbinia.worker.psq.Worker')
  @mock.patch('turbinia.lib.docker_manager.DockerManager')
  def testTurbiniaWorkerIsNonDir(self, _, __, ___, ____):
    """Test that OUTPUT_DIR does not point to an existing non-directory."""
    config.OUTPUT_DIR = os.path.join(self.tmp_dir, 'empty_file')
    open(config.OUTPUT_DIR, 'a').close()
    self.assertRaises(TurbiniaException, TurbiniaPsqWorker)

  @mock.patch('turbinia.worker.config')
  @mock.patch('turbinia.worker.check_directory')
  @mock.patch('turbinia.worker.pubsub')
  @mock.patch('turbinia.worker.datastore.Client')
  @mock.patch('turbinia.worker.psq.Worker')
  @mock.patch('turbinia.lib.docker_manager.DockerManager')
  def testTurbiniaWorkerJobsLists(self, _, __, ___, ____, _____, mock_config):
    """Test that worker job allowlist and denylists are setup correctly."""
    mock_config.PSQ_TOPIC = 'foo'
    manager.JobsManager._job_classes = {}
    manager.JobsManager.RegisterJob(manager_test.TestJob1)
    manager.JobsManager.RegisterJob(manager_test.TestJob2)
    manager.JobsManager.RegisterJob(manager_test.TestJob3)

    # Check denylist
    TurbiniaPsqWorker(['testjob1'], [])
    self.assertListEqual(
        sorted(list(manager.JobsManager.GetJobNames())),
        ['testjob2', 'testjob3'])
    manager.JobsManager.RegisterJob(manager_test.TestJob1)

    # Check denylist with DISABLED_JOBS config
    mock_config.DISABLED_JOBS = ['testjob1']
    TurbiniaPsqWorker(['testjob2'], [])
    self.assertListEqual(list(manager.JobsManager.GetJobNames()), ['testjob3'])
    manager.JobsManager.RegisterJob(manager_test.TestJob1)
    manager.JobsManager.RegisterJob(manager_test.TestJob2)
    mock_config.DISABLED_JOBS = ['']

    # Check allowlist
    TurbiniaPsqWorker([], ['testjob1'])
    self.assertListEqual(list(manager.JobsManager.GetJobNames()), ['testjob1'])
    manager.JobsManager.RegisterJob(manager_test.TestJob2)
    manager.JobsManager.RegisterJob(manager_test.TestJob3)

    # Check allowlist of item in DISABLED_JOBS config
    mock_config.DISABLED_JOBS = ['testjob1', 'testjob2']
    TurbiniaPsqWorker([], ['testjob1'])
    self.assertListEqual(list(manager.JobsManager.GetJobNames()), ['testjob1'])
    manager.JobsManager.RegisterJob(manager_test.TestJob2)
    manager.JobsManager.RegisterJob(manager_test.TestJob3)

  @mock.patch('turbinia.worker.subprocess.Popen')
  @mock.patch('logging.Logger.warning')
  def testSystemDependencyCheck(self, mock_logger, popen_mock):
    """Test system dependency check."""
    dependencies = {
        'plasojob': {
            'programs': ['non_exist'],
            'docker_image': None
        }
    }
    # Dependency not found.
    proc_mock = mock.MagicMock()
    proc_mock.communicate.return_value = (b'no', b'thing')
    proc_mock.returncode = 1
    popen_mock.return_value = proc_mock
    self.assertRaises(
        TurbiniaException, check_system_dependencies, dependencies)

    # Normal run.
    proc_mock.returncode = 0
    check_system_dependencies(dependencies)

    # Job not found.
    dependencies['non_exist'] = dependencies.pop('plasojob')
    check_system_dependencies(dependencies)
    mock_logger.assert_called_with(
        'The job non_exist was not found or has been disabled. '
        'Skipping dependency check...')

  @mock.patch('turbinia.lib.docker_manager.DockerManager')
  @mock.patch('turbinia.lib.docker_manager.ContainerManager')
  @mock.patch('logging.Logger.warning')
  def testDockerDependencyCheck(
      self, mock_logger, mock_contmgr, mock_dockermgr):
    """Test Docker dependency check."""
    dependencies = {
        'plasojob': {
            'programs': ['non_exist'],
            'docker_image': 'test_img'
        }
    }

    # Set up mock objects
    mock_dm = mock_dockermgr.return_value
    mock_dm.list_images.return_value = ['test_img']
    mock_cm = mock_contmgr.return_value

    # Dependency not found.
    mock_cm.execute_container.return_value = ['non_exist', None, 1]
    self.assertRaises(
        TurbiniaException, check_docker_dependencies, dependencies)

    # Normal run
    mock_cm.execute_container.return_value = ['exists', None, 0]
    check_docker_dependencies(dependencies)

    # Docker image not found
    mock_dm.list_images.return_value = ['non_exist']
    self.assertRaises(
        TurbiniaException, check_docker_dependencies, dependencies)

    # Job not found.
    dependencies['non_exist'] = dependencies.pop('plasojob')
    check_docker_dependencies(dependencies)
    mock_logger.assert_called_with(
        'The job non_exist was not found or has been disabled. '
        'Skipping dependency check...')
