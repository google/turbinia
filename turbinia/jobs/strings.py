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
"""Job to execute strings task."""

from __future__ import unicode_literals

from turbinia.evidence import DiskPartition
from turbinia.evidence import TextFile
from turbinia.jobs import interface
from turbinia.jobs import manager
from turbinia.workers.strings import StringsAsciiTask
from turbinia.workers.strings import StringsUnicodeTask


class StringsJob(interface.TurbiniaJob):
  """Strings collection Job.

  This will generate a Unicode and ASCII string collection task for each piece
  of evidence.
  """

  # The types of evidence that this Job will process
  evidence_input = [DiskPartition]
  evidence_output = [TextFile]

  NAME = 'StringsJob'

  def create_tasks(self, evidence):
    """Create task for Strings.

    Args:
      evidence: List of evidence objects to process

    Returns:
        A list of tasks to schedule.
    """
    # Generate tasks for both types of Strings jobs
    tasks = [StringsAsciiTask() for _ in evidence]
    tasks.extend([StringsUnicodeTask() for _ in evidence])
    return tasks


manager.JobsManager.RegisterJob(StringsJob)
