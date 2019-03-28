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
"""Job to execute HTTP Access logs analysis task."""
from __future__ import unicode_literals

from turbinia.workers import artifact

from turbinia.evidence import Directory
from turbinia.evidence import RawDisk
from turbinia.evidence import GoogleCloudDisk
from turbinia.evidence import GoogleCloudDiskRawEmbedded
from turbinia.evidence import ExportedFileArtifact
from turbinia.evidence import ReportText
from turbinia.jobs import interface
from turbinia.jobs import manager
from turbinia.workers.analysis import wordpress

ACCESS_LOG_ARTIFACTS = [
    'GKEDockerContainerLogs', 'NginxAccessLogs', 'ApacheAccessLogs'
]


class HTTPAccessLogExtractionJob(interface.TurbiniaJob):
  """HTTP Access log extraction job."""

  evidence_input = [
      Directory, RawDisk, GoogleCloudDisk, GoogleCloudDiskRawEmbedded
  ]

  evidence_output = [ExportedFileArtifact]

  NAME = 'HTTPAccessLogExtractionJob'

  def create_tasks(self, evidence):
    """Create task.

    Args:
      evidence: List of evidence objects to process

    Returns:
        A list of tasks to schedule.
    """
    tasks = []
    for artifact_name in ACCESS_LOG_ARTIFACTS:
      tasks.extend([
          artifact.FileArtifactExtractionTask(artifact_name) for _ in evidence
      ])
    return tasks


class HTTPAccessLogAnalysisJob(interface.TurbiniaJob):
  """HTTP Access log analysis job."""

  evidence_input = [ExportedFileArtifact]
  evidence_output = [ReportText]

  NAME = 'HTTPAccessLogAnalysisJob'

  def create_tasks(self, evidence):
    """Create task.
    Args:
      evidence: List of evidence objects to process
    Returns:
        A list of tasks to schedule.
    """
    evidence = [e for e in evidence if e.artifact_name in ACCESS_LOG_ARTIFACTS]
    return [wordpress.WordpressAccessLogAnalysisTask() for _ in evidence]


manager.JobsManager.RegisterJobs(
    [HTTPAccessLogExtractionJob, HTTPAccessLogAnalysisJob])
