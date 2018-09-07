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

import logging
import uuid

log = logging.getLogger('turbinia')


def get_jobs(jobs_blacklist=None, jobs_whitelist=None, jobs_list=None):
  """Gets a list of all job objects.

  Only one of jobs_blacklist and jobs_whitelist can be specified at a time,
  and all Jobs will be returned if both are specified.

  Args:
    jobs_blacklist (list): Jobs that will be excluded from running
    jobs_whitelist (list): The only Jobs will be included to run
    jobs_list (list): Instantiated jobs to select from (mostly used for testing)

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

  jobs_blacklist = jobs_blacklist if jobs_blacklist else []
  jobs_whitelist = jobs_whitelist if jobs_whitelist else []

  # TODO(aarontp): Dynamically look up job objects and make enabling/disabling
  # configurable through config and/or recipes.
  jobs = jobs_list if jobs_list else [
      StatJob(), PlasoJob(), PsortJob(), StringsJob(), GrepJob(),
      SSHDExtractionJob(), SSHDAnalysisJob(), TomcatExtractionJob(),
      TomcatAnalysisJob()]

  if jobs_whitelist and jobs_blacklist:
    log.info(
        'jobs_whitelist and jobs_blacklist cannot be specified at the same '
        'time.  Returning all Jobs instead.')
    return jobs
  elif jobs_blacklist:
    return [job for job in jobs if job.name not in jobs_blacklist]
  elif jobs_whitelist:
    return [job for job in jobs if job.name in jobs_whitelist]

  return jobs


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
