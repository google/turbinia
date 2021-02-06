# -*- coding: utf-8 -*-
# Copyright 2017 Google Inc.
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
"""Task for running Psort."""

from __future__ import unicode_literals

import os

from turbinia import config
from turbinia.workers import TurbiniaTask
from turbinia.evidence import PlasoCsvFile


class PsortTask(TurbiniaTask):
  """Task to run Psort to generate CSV output from plaso storage files."""

  def run(self, evidence, result):
    """Task that processes Plaso storage files with Psort.

    Args:
        evidence (Evidence object):  The evidence we will process.
        result (TurbiniaTaskResult): The object to place task results into.

    Returns:
        TurbiniaTaskResult object.
    """
    config.LoadConfig()

    psort_file = os.path.join(self.output_dir, '{0:s}.csv'.format(self.id))
    psort_evidence = PlasoCsvFile(source_path=psort_file)
    psort_log = os.path.join(self.output_dir, '{0:s}.log'.format(self.id))

    cmd = ['psort.py', '--status_view', 'none', '--logfile', psort_log]
    if config.DEBUG_TASKS or evidence.config.get('debug_tasks'):
      cmd.append('-d')

    cmd.extend(['--additional_fields', 'yara_match'])
    cmd.extend(['-w', psort_file, evidence.local_path])
    cmd.extend(['--temporary_directory', self.tmp_dir])

    result.log('Running psort as [{0:s}]'.format(' '.join(cmd)))

    self.execute(
        cmd, result, log_files=[psort_log], new_evidence=[psort_evidence],
        close=True)

    return result
