#!/usr/bin/env python
# Copyright 2015 Google Inc.
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
# -*- coding: utf-8 -*-
"""Tests that all jobs are imported correctly."""

from __future__ import unicode_literals

import io
import re
import os
import unittest


class JobImportTest(unittest.TestCase):
  """Tests that job classes are imported correctly."""

  _JOBS_PATH = os.path.abspath(os.path.dirname(__file__))

  _IGNORABLE_FILES = frozenset(['manager.py', 'interface.py'])

  _FILENAME_REGEXP = re.compile(r'^[^_]\w+\.py$')

  def _AssertFilesImportedInInit(self, path, ignorable_files):
    """Checks that files in path are imported in __init__.py

    Args:
      path (str): path to directory containing an __init__.py file and other
          Python files which should be imported.
      ignorable_files (Iterable[str]): names of Python files that don't need to
          appear in __init__.py. For example, 'manager.py'.
    """
    init_path = '{0:s}/__init__.py'.format(path)
    with io.open(init_path, mode='r', encoding='utf-8') as init_file:
      init_content = init_file.read()

    for file_path in os.listdir(path):
      filename = os.path.basename(file_path)
      if filename in ignorable_files:
        continue
      if filename.endswith('_test.py'):
        continue
      if self._FILENAME_REGEXP.search(filename):
        module_name, _, _ = filename.partition('.')
        import_expression = re.compile(r' import {0:s}\b'.format(module_name))

        self.assertRegexpMatches(
            init_content, import_expression,
            '{0:s} not imported in {1:s}'.format(module_name, init_path))

  def testJobsImported(self):
    """Tests that all jobs are imported."""
    self._AssertFilesImportedInInit(self._JOBS_PATH, self._IGNORABLE_FILES)


if __name__ == '__main__':
  unittest.main()
