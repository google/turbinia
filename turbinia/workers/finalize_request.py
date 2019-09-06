# -*- coding: utf-8 -*-
# Copyright 2019 Google Inc.
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
"""Task to finalize the request."""

from __future__ import unicode_literals

import os

from turbinia import config
from turbinia.evidence import FinalReport
from turbinia.workers import TurbiniaTask


class FinalizeRequestTask(TurbiniaTask):
  """Task to finalize the Turbinia request."""

  def run(self, evidence, result):
    """Main entry point for Task.

    This generates a final report.

    Args:
        evidence (EvidenceCollection): All Evidence that has been generated as
            part of this request.
        result (TurbiniaTaskResult): The result to place task output into.

    Returns:
        TurbiniaTaskResult: Task execution results.
    """
    # Doing a delayed import to avoid circular dependencies.
    from turbinia.client import TurbiniaClient
    report = FinalReport()
    client = TurbiniaClient()

    report_file = os.path.join(
        self.tmp_dir, 'final_turbinia_report_{0:s}.md'.format(self.id))
    report.local_path = report_file
    report_data = client.format_task_status(
        config.INSTANCE_ID, config.TURBINIA_PROJECT, config.TURBINIA_REGION,
        request_id=evidence.request_id, full_report=True)

    result.log('Writing report data to [{0:s}]'.format(report.local_path))
    with open(report.local_path, 'wb') as file_handle:
      file_handle.write(report_data.encode('utf-8'))

    result.add_evidence(report, evidence.config)
    result.close(self, True)
    return result
