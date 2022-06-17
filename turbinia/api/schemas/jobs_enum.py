# -*- coding: utf-8 -*-
# Copyright 2022 Google Inc.
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
"""Turbinia API server Job types enum."""

from enum import Enum


class JobsEnum(str, Enum):
  """Enum of the available Turbinia job types."""
  BulkExtractorJob = 'BulkExtractorJob'
  DfdeweyJob = 'DfdeweyJob'
  DockerContainersEnumerationJob = 'DockerContainersEnumerationJob'
  FileSystemTimelineJob = 'FileSystemTimelineJob'
  FsstatJob = 'FsstatJob'
  GrepJob = 'GrepJob'
  HadoopAnalysisJob = 'HadoopAnalysisJob'
  HindsightJob = 'HindsightJob'
  JenkinsAnalysisJob = 'JenkinsAnalysisJob'
  LinuxAccountAnalysisJob = 'LinuxAccountAnalysisJob'
  LokiAnalysisJob = 'LokiAnalysisJob'
  PartitionEnumerationJob = 'PartitionEnumerationJob'
  PlasoJob = 'PlasoJob'
  PhotorecJob = 'PhotorecJob'
  PsortJob = 'PsortJob'
  StringsJob = 'StringsJob'
  VolatilityJob = 'VolatilityJob'
  WindowsAccountAnalysisJob = 'WindowsAccountAnalysisJob'
  WordpressCredsAnalysisJob = 'WordpressCredsAnalysisJob'

  @classmethod
  def get_values(cls):
    """Return a dictionary of all enabled job types."""
    available_jobs = {'enabled_jobs': []}
    for job in cls:
      available_jobs['enabled_jobs'].append(job.value)
    return available_jobs
