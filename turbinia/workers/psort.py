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
  """Task to run Psort (Plaso toolset)."""

  TASK_CONFIG = {
      'status_view': 'none',
      'additional_fields': 'yara_match',
      'output_format': None,
      'profilers': None,
  }

  def build_plaso_command(self, base_command, conf):
    """ Builds a typical plaso command, contains logic specific to psort.

    Args:
      base_command (str): Command to invoke psort
      conf (dict): Dynamic config containing the parameters for the command.

    Returns:
      list: Plaso command and arguments
    """

    # Base command could be potentially placed in global configuration
    cmd = [base_command]
    for k, v in conf.items():
      cli_args = [
          'status_view', 'additional_fields', 'output_format', 'profilers'
      ]
      if (k not in cli_args or not v):
        continue
      prepend = '-'
      if len(k) > 1:
        prepend = '--'
      if isinstance(v, list):
        if v:
          cmd.extend([prepend + k, ','.join(v)])
      elif isinstance(v, bool):
        if v:
          cmd.append(prepend + k)
      elif isinstance(v, str):
        if v:
          cmd.extend([prepend + k, v])
    return cmd

  def run(self, evidence, result):
    """Task that processes Plaso storage files with Psort."""

    config.LoadConfig()

    psort_file = os.path.join(self.output_dir, '{0:s}.csv'.format(self.id))
    psort_evidence = PlasoCsvFile(source_path=psort_file)
    psort_log = os.path.join(self.output_dir, '{0:s}.log'.format(self.id))

    cmd = self.build_plaso_command('psort.py', self.task_config)

    cmd.extend(['--logfile', psort_log])
    if config.DEBUG_TASKS or self.task_config.get('debug_tasks'):
      cmd.append('-d')

    cmd.extend(['-w', psort_file, evidence.local_path])

    result.log('Running psort as [{0:s}]'.format(' '.join(cmd)))

    self.execute(
        cmd, result, log_files=[psort_log], new_evidence=[psort_evidence],
        close=True)

    return result
