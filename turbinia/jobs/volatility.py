# -*- coding: utf-8 -*-
# Copyright 2018 Google Inc.
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
"""Job to execute volatility tasks."""

from __future__ import unicode_literals

from turbinia.evidence import RawMemory
from turbinia.evidence import VolatilityReport
from turbinia.jobs import interface
from turbinia.jobs import manager
from turbinia.workers.volatility import VolatilityTask


class VolatilityJob(interface.TurbiniaJob):
  """Volatility analysis job.

  This will generate a Volatility task for every module per each peice of
  evidence.
  """

  evidence_input = [RawMemory]
  evidence_output = [VolatilityReport]

  NAME = 'VolatilityJob'

  def create_tasks(self, evidence):
    """Create task for Volatility.

    Args:
      evidence: List of evidence objects to process

    Returns:
      A list of tasks to schedule.
    """

    tasks = []
    for evidence_item in evidence:
      for mod in evidence_item.module_list:
        tasks.append(VolatilityTask(mod))
    return tasks


manager.JobsManager.RegisterJob(VolatilityJob)
