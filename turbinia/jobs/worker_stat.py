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
"""Job for running a stat call on the supplied evidence."""

from __future__ import unicode_literals

from turbinia.evidence import Directory
from turbinia.evidence import RawDisk
from turbinia.evidence import ReportText
from turbinia.jobs import interface
from turbinia.jobs import manager
from turbinia.workers.worker_stat import StatTask


class StatJob(interface.TurbiniaJob):
  """Job to run Stat."""

  # The types of evidence that this Job will process
  evidence_input = [RawDisk, Directory]
  evidence_output = [ReportText]

  NAME = 'StatJob'

  def create_tasks(self, evidence):
    """Create task for Stat.

    Args:
      evidence: List of evidence objects to process

    Returns:
        A list of StatTasks.
    """
    return [StatTask() for _ in evidence]


manager.JobsManager.RegisterJob(StatJob)
