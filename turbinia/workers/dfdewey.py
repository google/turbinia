# -*- coding: utf-8 -*-
# Copyright 2021 Google Inc.
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
"""Task for running dfDewey."""

from __future__ import unicode_literals

import os

from turbinia import config
from turbinia.evidence import EvidenceState as state
from turbinia.evidence import ReportText
from turbinia.workers import TurbiniaTask


class DfdeweyTask(TurbiniaTask):
  """Task to run dfDewey.

  This task requires dfDewey to be installed on the worker.
  https://github.com/google/dfdewey

  Additionally, dfDewey requires Elasticsearch and PostgreSQL datastores.
  For more information on datastore setup, see:
  https://github.com/google/dfdewey/blob/master/README.md#datastores
  """

  REQUIRED_STATES = [state.ATTACHED]

  # Task configuration variables from recipe
  TASK_CONFIG = {
      # Case ID for the disk being processed / searched
      'case': None,
      # Search term
      'search': None
  }

  def run(self, evidence, result):
    """Task to index a disk with dfDewey.

    Args:
        evidence (Evidence object):  The evidence we will process.
        result (TurbiniaTaskResult): The object to place task results into.

    Returns:
        TurbiniaTaskResult object.
    """

    config.LoadConfig()

    dfdewey_output = os.path.join(self.output_dir, 'dfdewey.txt')
    success = True
    status_summary = ''

    if self.task_config.get('case'):
      cmd = []
      # Datastore config
      config_vars = [
          configvar for configvar in dir(config)
          if configvar.startswith('DFDEWEY_')
      ]
      env = os.environ.copy()
      for configvar in config_vars:
        configval = getattr(config, configvar)
        if configvar != 'DFDEWEY_OS_URL' or configval:
          env[configvar] = '{0!s}'.format(getattr(config, configvar))

      cmd.append('dfdewey')
      cmd.append(self.task_config.get('case'))
      cmd.append(evidence.local_path)
      if self.task_config.get('search'):
        cmd.extend(['-s', self.task_config.get('search')])
      output_evidence = ReportText(source_path=dfdewey_output)

      result.log('Running dfDewey as [{0:s}]'.format(' '.join(cmd)))
      ret, _ = self.execute(
          cmd, result, stdout_file=dfdewey_output,
          new_evidence=[output_evidence], close=True, env=env)
      status_summary = 'dfDewey executed with [{0:s}]'.format(' '.join(cmd))
      if ret != 0:
        success = False
        status_summary = 'dfDewey execution failed. Return code: {0:d}'.format(
            ret)
        result.log(status_summary)
    else:
      status_summary = (
          'Not running dfDewey. Case was not provided in task config.')
      result.log(status_summary)

    result.close(self, success=success, status=status_summary)
    return result
