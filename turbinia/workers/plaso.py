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

import json
import os
import subprocess

from turbinia.workers import TurbiniaTask
from turbinia.workers import TurbiniaTaskResult


class PlasoTask(TurbiniaTask):
  """Task to run Plaso (log2timeline)."""

  def run(self, evidence, out_path, job_id, **kwargs):
    """Task that process data with Plaso.

    Args:
        evidence: Path to data to process.
        out_path: Path to temporary storage of results.
        job_id: Unique ID for this task.

    Returns:
        Task result object (instance of TurbiniaTaskResult) as JSON.
    """
    out_path = '{0:s}/{1:s}'.format(out_path, job_id)
    if not os.path.exists(out_path):
      os.makedirs(out_path)
    cmd_output = subprocess.check_output(
        ['/usr/local/bin/plaso_wrapper.sh', src_path, out_path, job_id])
    res, version, metadata = cmd_output.split(' ', 2)
    result = TurbiniaTaskResult(version=version, metadata=json.loads(metadata))
    result.add_result(result_type='PATH', result=res)
    return result
