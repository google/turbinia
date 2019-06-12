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
"""Job to execute Hindsight tasks."""

from __future__ import unicode_literals

from turbinia.evidence import ChromiumProfile
from turbinia.evidence import TextFile
from turbinia.jobs import interface
from turbinia.jobs import manager
from turbinia.workers.hindsight import HindsightTask


class HindsightJob(interface.TurbiniaJob):
  """Hindsight analysis job.
    This will execute hindsight against a piece of evidence.
    """

  evidence_input = [ChromiumProfile]
  evidence_output = [TextFile]

  NAME = 'HindsightJob'

  def create_tasks(self, evidence):
    """Create task.
        Args:
            evidence: List of evidence objects to process
        Returns:
            A list of tasks to schedule.
        """

    tasks = [HindsightTask() for _ in evidence]
    return tasks


manager.JobsManager.RegisterJob(HindsightJob)
