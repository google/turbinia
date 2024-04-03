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

import unittest
import argparse

from unittest import mock

from turbinia import config
from turbinia import turbiniactl


class TestTurbiniactl(unittest.TestCase):
  """ Test Turbiniactl."""

  @mock.patch('turbinia.output_manager.OutputManager.setup')
  @mock.patch('turbinia.output_manager.OutputManager.save_evidence')
  # pylint: disable=arguments-differ
  def setUp(self, _, __):
    super(TestTurbiniactl, self).setUp()
    config.TASK_MANAGER = 'celery'

  def testInvalidCommand(self):
    """Test an invalid command."""
    args = argparse.Namespace(command='badCommand')
    self.assertRaises((argparse.ArgumentError, SystemExit),
                      turbiniactl.process_args, [args.command])

  @mock.patch('turbinia.worker.TurbiniaCeleryWorker')
  def testCeleryWorkerCommand(self, mock_worker):
    """Test CeleryWorker command."""
    args = argparse.Namespace(command='celeryworker')
    turbiniactl.process_args([args.command])
    mock_worker.assert_called_once_with(jobs_denylist=[], jobs_allowlist=[])

  @mock.patch('turbinia.config.ParseDependencies')
  @mock.patch('turbinia.worker.TurbiniaCeleryWorker.start')
  def testCeleryWorkerCommandStart(self, mock_worker, _):
    """Test CeleryWorker start."""
    args = argparse.Namespace(command='celeryworker')
    turbiniactl.process_args([args.command])
    mock_worker.assert_called_once_with()

  @mock.patch('turbinia.server.TurbiniaServer')
  def testServerCommand(self, mock_server):
    """Test Server command."""
    args = argparse.Namespace(command='server')
    turbiniactl.process_args([args.command])
    mock_server.assert_called_once_with(jobs_denylist=[], jobs_allowlist=[])

  @mock.patch('turbinia.task_manager.CeleryTaskManager._backend_setup')
  @mock.patch('turbinia.server.TurbiniaServer.start')
  def testServerCommandStart(self, mock_server, _):
    """Test Server start."""
    args = argparse.Namespace(command='server')
    turbiniactl.process_args([args.command])
    mock_server.assert_called_once_with()

  @mock.patch('turbinia.api.api_server.TurbiniaAPIServer')
  def testAPIServerCommand(self, mock_api_server):
    """Test API server command."""
    args = argparse.Namespace(command='api_server')
    turbiniactl.process_args([args.command])
    mock_api_server.assert_called_once_with()

  @mock.patch('turbinia.api.api_server.TurbiniaAPIServer.start')
  def testAPIServerCommandStart(self, mock_api_server):
    """Test API server start."""
    args = argparse.Namespace(command='api_server')
    turbiniactl.process_args([args.command])
    mock_api_server.assert_called_once_with('turbinia.api.api_server:app')
