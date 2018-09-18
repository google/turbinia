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
"""Tests for libcloudforensics module."""

from __future__ import unicode_literals

import unittest

import mock
import six

from turbinia.lib import libcloudforensics


class GoogleCloudProjectTest(unittest.TestCase):
  """Test Google Cloud project class."""

  def setUp(self):
    self.project = libcloudforensics.GoogleCloudProject('test-project')
    self.project.GceApi = mock.MagicMock()
    self.project.GceOperation = mock.MagicMock()

  def testFormatLogMessage(self):
    """Test formatting log message"""
    msg = 'Test message'
    formatted_msg = self.project.format_log_message(msg)
    self.assertIsInstance(formatted_msg, six.string_types)
    self.assertEqual(
        formatted_msg, u'project:{0:s} {1:s}'.format(
            self.project.project_id, msg))
