# -*- coding: utf-8 -*-
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
"""Task for filter a text file using regular expression patterns."""

from __future__ import unicode_literals

import os

from turbinia.evidence import TextFile
from turbinia.workers import TurbiniaTask


class GrepTask(TurbiniaTask):
  """Filter input based on regular expression patterns."""

  def run(self, evidence, result):
    """Run grep binary.

    Args:
        evidence (Evidence object):  The evidence we will process
        result (TurbiniaTaskResult): The object to place task results into.

    Returns:
        TurbiniaTaskResult object.
    """
    output_evidence = TextFile()

    # TODO(jbn): Pick this up from evidence.recipe instead.
    patterns = ['foo', 'bar']
    with open('foo.txt', 'wb') as fh:
      fh.write('\n'.join(patterns))

    # Create a path that we can write the new file to.
    base_name = os.path.basename(evidence.local_path)
    output_file_path = os.path.join(
        self.output_dir, '{0:s}.filtered'.format(base_name))

    output_evidence.local_path = output_file_path
    cmd = 'grep -E -b -n -f {0:s} > {1:s}'.format(
      evidence.local_path, output_file_path)

    result.log('Running [{0:s}]'.format(cmd))

    self.execute(
      cmd, result, new_evidence=[output_evidence], close=True, shell=True)

    return result
