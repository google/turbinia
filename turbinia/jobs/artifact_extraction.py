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
"""job to conditionally extract artifacts from a filesystem image"""

from __future__ import unicode_literals

from turbinia.evidence import Directory
from turbinia.evidence import GoogleCloudDisk
from turbinia.evidence import GoogleCloudDiskRawEmbedded
from turbinia.evidence import ExportedFileArtifact
from turbinia.evidence import RawDisk
from turbinia.evidence import ReportText
from turbinia.jobs import interface
from turbinia.jobs import manager
from turbinia.workers.artifact import FileArtifactExtractionTask


class ArtifactExtractionJob(interface.TurbiniaJob):
  """ Extract artifacts specificed in the evidence recipe """
  evidence_input = [
      Directory, RawDisk, GoogleCloudDisk, GoogleCloudDiskRawEmbedded
  ]

  evidence_output = [ExportedFileArtifact]
  NAME = "ArtifactExtractionJob"

  def create_tasks(self, evidence):
    """Create task.

    Args:
      evidence: List of evidence objects to process

    Returns:
        A list of tasks to schedule.
    """
    #Retrieve appropriabe base config
    task_recipe = self.evidence.config.get('FileArtifactExtractionTask', None)
    if task_recipe:
      tasks = []
      for variant in task_recipe['variant']:
        for _ in evidence:
          new_task = FileArtifactExtractionTask(task_variant=variant)
          if self.validate_task_conf(new_task.task_conf, task_recipe[variant]):
            tasks.append(new_task)
    else:
      tasks = [FileArtifactExtractionTask() for _ in evidence]
    return tasks


manager.JobsManager.RegisterJobs([ArtifactExtractionJob])
