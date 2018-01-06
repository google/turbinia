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
"""Job to execute Psort task."""

from turbinia.evidence import PlasoFile
from turbinia.evidence import PlasoCsvFile
from turbinia.jobs import TurbiniaJob
from turbinia.workers.psort import PsortTask


class PsortJob(TurbiniaJob):
  """Run psort on PlasoFile to generate a CSV file."""

  # The types of evidence that this Job will process
  evidence_input = [type(PlasoFile())]
  evidence_output = [type(PlasoCsvFile())]

  def __init__(self):
    super(PsortJob, self).__init__(name='PsortJob')

  def create_tasks(self, evidence):
    """Create task for Psort.

    Args:
      evidence: List of evidence object to process

    Returns:
        A list of PsortTasks.
    """
    return [PsortTask() for e in evidence]
