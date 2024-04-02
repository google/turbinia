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
import tempfile

from unittest import mock

from turbinia import config
from turbinia import turbiniactl
from turbinia.lib import recipe_helpers
from turbinia.message import TurbiniaRequest


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

  def testInvalidCommand(self):
    """Test an invalid command."""
    args = argparse.Namespace(command='badCommand')
    self.assertRaises(
        (argparse.ArgumentError,SystemExit),
        turbiniactl.process_args, [args.command])
