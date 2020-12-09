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
"""Task for running a test evidence stat call on the supplied evidence.

TODO(aarontp): In the future we can use this for doing a count and healthcheck
               of all PSQ workers since there is currently no mechanism for that
               in PSQ.
"""

from __future__ import unicode_literals

import os

from turbinia.workers import TurbiniaTask
from turbinia.evidence import ReportText


class StatTask(TurbiniaTask):
  """Task to run Stat."""

  def run(self, evidence, result):
    """Test Stat task.

    Args:
        evidence: Path to data to process.
        result: TurbiniaTaskResult to populate with results.

    Returns:
        TurbiniaTaskResult: object.
    """
    result.log('Running stat on evidence {0:s}'.format(evidence.local_path))
    report_path = os.path.join(self.output_dir, 'report.txt')
    report = ReportText(source_path=report_path)
    report.text_data = str(os.stat(evidence.local_path))
    with open(report_path, 'w') as f:
      f.write(report.text_data)

    result.add_evidence(report, evidence.config)
    result.close(self, success=True)

    return result
