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

from __future__ import unicode_literals

from turbinia.evidence import PlasoFile
from turbinia.evidence import PlasoCsvFile
from turbinia.jobs import interface
from turbinia.jobs import manager
from turbinia.workers.psort import PsortTask


class PsortJob(interface.TurbiniaJob):
  """Run psort on PlasoFile to generate a CSV file."""

  # The types of evidence that this Job will process
  evidence_input = [PlasoFile]
  evidence_output = [PlasoCsvFile]

  NAME = 'PsortJob'

  def create_tasks(self, evidence):
    """Create task for Psort.

    Args:
      evidence: List of evidence objects to process

    Returns:
        A list of PsortTasks.
    """
    return [PsortTask() for _ in evidence]


manager.JobsManager.RegisterJob(PsortJob)
