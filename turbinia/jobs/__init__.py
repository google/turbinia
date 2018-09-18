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
"""Turbinia jobs."""

import uuid


def get_jobs():
  """Gets a list of all job objects.

  Returns:
    A list of TurbiniaJobs.
  """
  # Defer imports to prevent circular dependencies during init.
  from turbinia.jobs.plaso import PlasoJob
  from turbinia.jobs.psort import PsortJob
  from turbinia.jobs.grep import GrepJob
  from turbinia.jobs.worker_stat import StatJob
  from turbinia.jobs.strings import StringsJob
  from turbinia.jobs.sshd import SSHDExtractionJob
  from turbinia.jobs.sshd import SSHDAnalysisJob
  from turbinia.jobs.tomcat import TomcatExtractionJob
  from turbinia.jobs.tomcat import TomcatAnalysisJob
  from turbinia.jobs.analysis.http_access_logs import HTTPAccessLogExtractionJob
  from turbinia.jobs.analysis.http_access_logs import HTTPAccessLogAnalysisJob
  from turbinia.jobs.analysis.jenkins import JenkinsAnalysisJob
  # TODO(aarontp): Dynamically look up job objects and make enabling/disabling
  # configurable through config and/or recipes.
  return [
      StatJob(), PlasoJob(), PsortJob(), StringsJob(), GrepJob(),
      SSHDExtractionJob(), SSHDAnalysisJob(), HTTPAccessLogExtractionJob(),
      HTTPAccessLogAnalysisJob(), TomcatExtractionJob(), TomcatAnalysisJob(),
      JenkinsAnalysisJob()]


class TurbiniaJob(object):
  """Base class for Turbinia Jobs.

  Attributes:
    name: Name of Job
    id: Id of job
    priority: Job priority from 0-100, lowest == highest priority
  """

  def __init__(self, name=None):
    self.name = name
    self.id = uuid.uuid4().hex
    self.priority = 100

  def create_tasks(self, evidence_):
    """Create Turbinia tasks to be run.

    Args:
      evidence_: A list of evidence objects

    Returns:
      A List of TurbiniaTask objects.
    """
    raise NotImplementedError
