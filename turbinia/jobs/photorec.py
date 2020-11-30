# -*- coding: utf-8 -*-
# Copyright 2020 Google Inc.
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
"""Job to run photorec Task."""
from __future__ import unicode_literals
from turbinia.evidence import RawDiskPartition
from turbinia.evidence import GoogleCloudDisk
from turbinia.evidence import GoogleCloudDiskRawEmbedded
from turbinia.jobs import interface
from turbinia.jobs import manager
from turbinia.evidence import PhotorecOutput
from turbinia.workers.photorec import PhotorecTask


class PhotorecJob(interface.TurbiniaJob):

  evidence_input = [
      RawDiskPartition, GoogleCloudDisk, GoogleCloudDiskRawEmbedded
  ]
  evidence_output = [PhotorecOutput]

  NAME = 'PhotorecJob'

  def create_tasks(self, evidence):
    """Create task for Plaso.

    Args:
      evidence: List of evidence objects to process

    Returns:
        A list of PlasoTasks.
    """
    return [PhotorecTask() for _ in evidence]


manager.JobsManager.RegisterJob(PhotorecJob)
