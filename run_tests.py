# -*- coding: utf-8 -*-
# Copyright 2016 Google Inc.
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
"""Script to run the tests."""

import os
import sys
import unittest

if __name__ == '__main__':
  base_dir = os.path.dirname(os.path.abspath(__file__))
  # Change PYTHONPATH to include full path to turbinia.
  sys.path.insert(0, base_dir)

  test_suite = unittest.TestLoader().discover(
      os.path.join(base_dir, 'tests'), pattern='*.py')
  test_results = unittest.TextTestRunner(verbosity=2).run(test_suite)
  if not test_results.wasSuccessful():
    sys.exit(1)
