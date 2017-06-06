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

import os
import subprocess

from turbinia.workers import TurbiniaTask
from turbinia.evidence import PlasoFile


class PlasoTask(TurbiniaTask):
  """Task to run Plaso (log2timeline)."""

  def run(self, evidence):
    """Task that process data with Plaso.

    Args:
        evidence: Path to data to process.

    Returns:
        TurbiniaTaskResult object.
    """
    result = self.setup(evidence)
    plaso_result = PlasoFile()

    plaso_file = os.path.join(self.output_dir, u'{0:s}.plaso'.format(self.id))
    plaso_log = os.path.join(self.output_dir, u'{0:s}.log'.format(self.id))

    # TODO(aarontp): Move these flags into a recipe
    cmd = (
        u'log2timeline.py -q --status_view none --hashers all '
        u'--partition all --vss_stores all').split()
    cmd.extend([u'--logfile', plaso_log])
    cmd.extend([plaso_file, evidence.local_path])

    result.log(u'Running plaso as [{0:s}]'.format(' '.join(cmd)))

    # TODO(aarontp): Create helper function to do all this
    plaso_proc = subprocess.Popen(cmd)
    stdout, stderr = plaso_proc.communicate()
    result.error['stdout'] = stdout
    result.error['stderr'] = stderr
    ret = plaso_proc.returncode

    if ret:
      msg = u'Plaso execution failed with status {0:s}'.format(ret)
      result.log(msg)
      result.close(success=False, status=msg)
    else:
      # TODO(aarontp): Get and set plaso version here
      result.log('Plaso output file in {0:s}'.format(plaso_file))
      plaso_result.local_path = plaso_file
      result.add_evidence(plaso_result)
      result.close(success=True)

    return result
