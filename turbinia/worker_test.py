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

import unittest
import os
import shutil
import tempfile

import mock

from turbinia import config
from turbinia.worker import TurbiniaCeleryWorker
from turbinia.worker import check_system_dependencies
from turbinia.worker import check_docker_dependencies
from turbinia.jobs import manager
from turbinia.jobs import manager_test
from turbinia import TurbiniaException


class TestTurbiniaCeleryWorker(unittest.TestCase):
  """Test Turbinia Celery Worker class."""

  def setUp(self):
    self.tmp_dir = tempfile.mkdtemp(prefix='turbinia-test')
    config.LoadConfig()
    config.OUTPUT_DIR = self.tmp_dir
    config.MOUNT_DIR_PREFIX = self.tmp_dir
    config.ParseDependencies = mock.MagicMock(return_value={})
    self.saved_jobs = manager.JobsManager._job_classes

  def tearDown(self):
    manager.JobsManager._job_classes = self.saved_jobs
    manager.JobsManager._job_classes['plasojob'].docker_image = None

    if 'turbinia-test' in self.tmp_dir:
      shutil.rmtree(self.tmp_dir)

  @mock.patch('turbinia.client.task_manager.CeleryTaskManager._backend_setup')
  @mock.patch('turbinia.lib.docker_manager.DockerManager')
  def testTurbiniaCeleryWorkerInit(self, _, __):
    """Basic test for Celery worker."""
    worker = TurbiniaCeleryWorker([], [])
    self.assertTrue(hasattr(worker, 'worker'))

  @mock.patch('turbinia.client.task_manager.CeleryTaskManager._backend_setup')
  @mock.patch('turbinia.lib.docker_manager.DockerManager')
  def testTurbiniaWorkerNoDir(self, _, __):
    """Test that OUTPUT_DIR path is created."""
    config.OUTPUT_DIR = os.path.join(self.tmp_dir, 'no_such_dir')
    TurbiniaCeleryWorker([], [])
    self.assertTrue(os.path.exists(config.OUTPUT_DIR))

  @mock.patch('turbinia.client.task_manager.CeleryTaskManager._backend_setup')
  @mock.patch('turbinia.lib.docker_manager.DockerManager')
  def testTurbiniaWorkerIsNonDir(self, _, __):
    """Test that OUTPUT_DIR does not point to an existing non-directory."""
    config.OUTPUT_DIR = os.path.join(self.tmp_dir, 'empty_file')
    open(config.OUTPUT_DIR, 'a').close()
    self.assertRaises(TurbiniaException, TurbiniaCeleryWorker)

  @mock.patch('turbinia.worker.config')
  @mock.patch('turbinia.worker.check_directory')
  @mock.patch('turbinia.client.task_manager.CeleryTaskManager._backend_setup')
  @mock.patch('turbinia.lib.docker_manager.DockerManager')
  def testTurbiniaWorkerJobsLists(self, _, __, ___, mock_config):
    """Test that worker job allowlist and denylists are setup correctly."""
    manager.JobsManager._job_classes = {}
    manager.JobsManager.RegisterJob(manager_test.TestJob1)
    manager.JobsManager.RegisterJob(manager_test.TestJob2)
    manager.JobsManager.RegisterJob(manager_test.TestJob3)

    # Check denylist
    TurbiniaCeleryWorker(['testjob1'], [])
    self.assertListEqual(
        sorted(list(manager.JobsManager.GetJobNames())),
        ['testjob2', 'testjob3'])
    manager.JobsManager.RegisterJob(manager_test.TestJob1)

    # Check denylist with DISABLED_JOBS config
    mock_config.DISABLED_JOBS = ['testjob1']
    TurbiniaCeleryWorker(['testjob2'], [])
    self.assertListEqual(list(manager.JobsManager.GetJobNames()), ['testjob3'])
    manager.JobsManager.RegisterJob(manager_test.TestJob1)
    manager.JobsManager.RegisterJob(manager_test.TestJob2)
    mock_config.DISABLED_JOBS = ['']

    # Check allowlist
    TurbiniaCeleryWorker([], ['testjob1'])
    self.assertListEqual(list(manager.JobsManager.GetJobNames()), ['testjob1'])
    manager.JobsManager.RegisterJob(manager_test.TestJob2)
    manager.JobsManager.RegisterJob(manager_test.TestJob3)

    # Check allowlist of item in DISABLED_JOBS config
    mock_config.DISABLED_JOBS = ['testjob1', 'testjob2']
    TurbiniaCeleryWorker([], ['testjob1'])
    self.assertListEqual(list(manager.JobsManager.GetJobNames()), ['testjob1'])
    manager.JobsManager.RegisterJob(manager_test.TestJob2)
    manager.JobsManager.RegisterJob(manager_test.TestJob3)

  @mock.patch('turbinia.worker.config')
  @mock.patch('turbinia.worker.subprocess.Popen')
  @mock.patch('logging.Logger.warning')
  def testSystemDependencyCheck(self, mock_logger, popen_mock, mock_config):
    """Test system dependency check."""
    dependencies = {
        'plasojob': {
            'programs': ['non_exist'],
            'docker_image': None
        }
    }
    mock_config.DOCKER_ENABLED = True
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

  @mock.patch('turbinia.worker.config')
  @mock.patch('turbinia.lib.docker_manager.DockerManager')
  @mock.patch('turbinia.lib.docker_manager.ContainerManager')
  @mock.patch('logging.Logger.warning')
  def testDockerDependencyCheck(
      self, mock_logger, mock_contmgr, mock_dockermgr, mock_config):
    """Test Docker dependency check."""
    dependencies = {
        'plasojob': {
            'programs': ['non_exist'],
            'docker_image': 'test_img'
        }
    }
    mock_config.DOCKER_ENABLED = True

    # Set up mock objects
    mock_dm = mock_dockermgr.return_value
    mock_cm = mock_contmgr.return_value

    # Image not found.
    mock_dm.image_exists.return_value = False
    self.assertRaises(
        TurbiniaException, check_docker_dependencies, dependencies)

    # # Uncomment when the program dependency program check is uncommented
    # # in worker.py as well.
    # # Dependency not found.
    # mock_cm.execute_container.return_value = ['non_exist', None, 1]
    # self.assertRaises(
    #     TurbiniaException, check_docker_dependencies, dependencies)

    dependencies = {
        'plasojob': {
            'programs': ['log2timeline'],
            'docker_image': 'log2timeline/plaso'
        }
    }
    # Normal run
    mock_dm.image_exists.return_value = True
    mock_cm.execute_container.return_value = ['exists', None, 0]
    check_docker_dependencies(dependencies)

    # Job not found.
    dependencies['non_exist'] = dependencies.pop('plasojob')
    check_docker_dependencies(dependencies)
    mock_logger.assert_called_with(
        'The job non_exist was not found or has been disabled. '
        'Skipping dependency check...')
