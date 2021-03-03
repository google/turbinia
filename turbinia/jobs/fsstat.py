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
"""Job to run fsstat Task."""
from __future__ import unicode_literals
from turbinia.evidence import DiskPartition
from turbinia.jobs import interface
from turbinia.jobs import manager
from turbinia.evidence import ReportText
from turbinia.workers.fsstat import FsstatTask


class FsstatJob(interface.TurbiniaJob):

  evidence_input = [DiskPartition]
  evidence_output = [ReportText]

  NAME = 'FsstatJob'

  def create_tasks(self, evidence):
    """Create task for Fsstat.

    Args:
      evidence: List of evidence objects to process

    Returns:
        A list of FsstatTasks.
    """
    return [FsstatTask() for _ in evidence]


manager.JobsManager.RegisterJob(FsstatJob)