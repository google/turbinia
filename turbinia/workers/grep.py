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
"""Task to filter a text file using extended regular expression patterns."""

from __future__ import unicode_literals

import os

from turbinia.evidence import FilteredTextFile
from turbinia.workers import TurbiniaTask
from turbinia.lib.file_helpers import write_list_to_temp_file


class GrepTask(TurbiniaTask):
  """Filter input based on extended regular expression patterns."""

  TASK_CONFIG = {'filter_patterns': []}

  def run(self, evidence, result):
    """Run grep binary.

    Args:
        evidence (Evidence object):  The evidence we will process
        result (TurbiniaTaskResult): The object to place task results into.

    Returns:
        TurbiniaTaskResult object.
    """

    patterns = self.task_config.get('filter_patterns')
    if not patterns:
      result.close(self, success=True, status='No patterns supplied, exit task')
      return result

    patterns_file_path = write_list_to_temp_file(patterns)

    # Create a path that we can write the new file to.
    base_name = os.path.basename(evidence.local_path)
    output_file_path = os.path.join(
        self.output_dir, '{0:s}.filtered'.format(base_name))

    output_evidence = FilteredTextFile(source_path=output_file_path)
    cmd = 'grep -E -b -n -f {0:s} {1:s} > {2:s}'.format(
        patterns_file_path, evidence.local_path, output_file_path)

    result.log('Running [{0:s}]'.format(cmd))
    ret, result = self.execute(
        cmd, result, new_evidence=[output_evidence], shell=True,
        success_codes=[0, 1])

    # Grep returns 0 on success and 1 if no results are found.
    if ret == 0:
      status = 'Grep Task found results in {0:s}'.format(evidence.name)
      result.close(self, success=True, status=status)
    elif ret == 1:
      status = 'Grep Task did not find any results in {0:s}'.format(
          evidence.name)
      result.close(self, success=True, status=status)
    else:
      result.close(self, success=False)

    return result
