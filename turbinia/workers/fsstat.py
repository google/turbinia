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
"""Task to run fsstat on disk partitions."""
from __future__ import unicode_literals

import os

from turbinia import TurbiniaException
from turbinia.workers import TurbiniaTask
from turbinia.evidence import EvidenceState as state
from turbinia.evidence import ReportText


class FsstatTask(TurbiniaTask):

  REQUIRED_STATES = [state.ATTACHED]

  def run(self, evidence, result):
    """Task to execute fsstat.

    Args:
        evidence (Evidence object):  The evidence we will process.
        result (TurbiniaTaskResult): The object to place task results into.

    Returns:
        TurbiniaTaskResult object.
    """
    fsstat_output = os.path.join(self.output_dir, 'fsstat.txt')
    output_evidence = ReportText(source_path=fsstat_output)
    cmd = ['sudo', 'fsstat', evidence.device_path]
    result.log('Running fsstat as [{0!s}]'.format(cmd))
    self.execute(
        cmd, result, stdout_file=fsstat_output, new_evidence=[output_evidence],
        close=True)

    return result