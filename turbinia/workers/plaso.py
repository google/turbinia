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
"""Task for running Plaso."""

from __future__ import unicode_literals

import os

from turbinia import config
from turbinia.evidence import PlasoFile
from turbinia.workers import TurbiniaTask


class PlasoTask(TurbiniaTask):
  """Task to run Plaso (log2timeline)."""

  def run(self, evidence, result):
    """Task that process data with Plaso.

    Args:
        evidence: Path to data to process.
        result: A TurbiniaTaskResult object to place task results into.

    Returns:
        TurbiniaTaskResult object.
    """
    config.LoadConfig()
    plaso_evidence = PlasoFile()

    plaso_file = os.path.join(self.output_dir, '{0:s}.plaso'.format(self.id))
    plaso_evidence.local_path = plaso_file
    plaso_log = os.path.join(self.output_dir, '{0:s}.log'.format(self.id))

    # TODO(aarontp): Move these flags into a recipe
    cmd = (
        'log2timeline.py --status_view none --hashers all '
        '--partition all --vss_stores all').split()
    if config.DEBUG_TASKS:
      cmd.append('-d')
    cmd.extend(['--logfile', plaso_log])
    cmd.extend([plaso_file, evidence.local_path])

    result.log('Running plaso as [{0:s}]'.format(' '.join(cmd)))

    self.execute(cmd, result, save_files=[plaso_log],
                 new_evidence=[plaso_evidence], close=True)

    return result
