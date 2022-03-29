#-*- coding: utf-8 -*-
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
"""Job utility methods for Turbinia."""

import logging

from turbinia import config
from turbinia.jobs import manager as job_manager

log = logging.getLogger('turbinia')

config.LoadConfig()


def register_job_timeouts(dependencies):
  """Registers a timeout for each job.

  Args:
    dependencies(dict): dependencies to grab timeout value from.
  """
  log.info('Registering job timeouts.')
  timeout_default = 3600

  job_names = list(job_manager.JobsManager.GetJobNames())
  # Iterate through list of jobs
  for job, values in dependencies.items():
    if job not in job_names:
      continue
    timeout = values.get('timeout')
    if not isinstance(timeout, int):
      log.warning(
          'No timeout found for job: {0:s}. Setting default timeout of {1:d} seconds.'
          .format(job, timeout_default))
      timeout = timeout_default
    job_manager.JobsManager.RegisterTimeout(job, timeout)