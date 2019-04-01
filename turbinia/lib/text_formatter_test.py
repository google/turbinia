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
"""Tests for text_formatter."""

from __future__ import unicode_literals

import unittest

from turbinia.lib import text_formatter as fmt


class TextFormatterTest(unittest.TestCase):
  """Tests for text_formatter methods."""

  def setUp(self):
    self.test_string = 'testing'

  def testFormatting(self):
    """Test text formatting."""
    self.assertEqual('**testing**', fmt.bold(self.test_string))
    self.assertEqual('# testing', fmt.heading1(self.test_string))
    self.assertEqual('## testing', fmt.heading2(self.test_string))
    self.assertEqual('### testing', fmt.heading3(self.test_string))
    self.assertEqual('#### testing', fmt.heading4(self.test_string))
    self.assertEqual('##### testing', fmt.heading5(self.test_string))
    self.assertEqual('* testing', fmt.bullet(self.test_string))
    self.assertEqual('        * testing', fmt.bullet(self.test_string, level=3))
    self.assertEqual('`testing`', fmt.code(self.test_string))
