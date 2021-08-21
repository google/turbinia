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
"""This file contains a class for managing jobs."""

from __future__ import unicode_literals

from turbinia import TurbiniaException

DEFAULT_TIMEOUT = 7200


class JobsManager:
  """The jobs manager."""

  _job_classes = {}

  @classmethod
  def FilterJobNames(cls, job_names, jobs_denylist=None, jobs_allowlist=None):
    """Filters a list of job names against white/black lists.

    jobs_allowlist and jobs_denylist must not be specified at the same time.

    Args:
      job_names (list[str]): The names of the job_names to filter.
      jobs_denylist (Optional[list[str]]): Job names to exclude.
      jobs_allowlist (Optional[list[str]]): Job names to include.

    Returns:
     list[str]: Job names

    Raises:
      TurbiniaException if both jobs_denylist and jobs_allowlist are specified.
    """
    jobs_denylist = jobs_denylist if jobs_denylist else []
    jobs_denylist = [job.lower() for job in jobs_denylist]
    jobs_allowlist = jobs_allowlist if jobs_allowlist else []
    jobs_allowlist = [job.lower() for job in jobs_allowlist]

    if jobs_allowlist and jobs_denylist:
      raise TurbiniaException(
          'jobs_allowlist and jobs_denylist cannot be specified at the same '
          'time.')
    elif jobs_denylist:
      return [job for job in job_names if job.lower() not in jobs_denylist]
    elif jobs_allowlist:
      return [job for job in job_names if job.lower() in jobs_allowlist]
    else:
      return job_names

  @classmethod
  def FilterJobObjects(cls, jobs, jobs_denylist=None, jobs_allowlist=None):
    """Filters a list of job objects against white/black lists.

    jobs_allowlist and jobs_denylist must not be specified at the same time.

    Args:
      jobs (list[TurbiniaJob]): The jobs to filter.
      jobs_denylist (Optional[list[str]]): Job names to exclude.
      jobs_allowlist (Optional[list[str]]): Job names to include.

    Returns:
     list[TurbiniaJob]: Job objects
    """
    job_names = [job.NAME.lower() for job in jobs]
    job_names = cls.FilterJobNames(job_names, jobs_denylist, jobs_allowlist)
    return [job for job in jobs if job.NAME.lower() in job_names]

  @classmethod
  def DeregisterJob(cls, job_class):
    """Deregisters a job class.

    The job classes are identified based on their lower case name.

    Args:
      job_class (type): class object of the job.

    Raises:
      KeyError: if job class is not set for the corresponding name.
    """
    job_name = job_class.NAME.lower()
    if job_name not in cls._job_classes:
      raise KeyError('job class not set for name: {0:s}'.format(job_class.NAME))

    del cls._job_classes[job_name]

  @classmethod
  def DeregisterJobs(cls, jobs_denylist=None, jobs_allowlist=None):
    """Deregisters a list of job names against white/black lists.

    jobs_allowlist and jobs_denylist must not be specified at the same time.

    Args:
      jobs_denylist (Optional[list[str]]): Job names to deregister.
      jobs_allowlist (Optional[list[str]]): Job names to register.

    Raises:
      TurbiniaException if both jobs_denylist and jobs_allowlist are specified.
    """
    registered_jobs = list(cls.GetJobNames())
    jobs_remove = []
    # Create a list of jobs to deregister.
    if jobs_allowlist and jobs_denylist:
      raise TurbiniaException(
          'jobs_allowlist and jobs_denylist cannot be specified at the same '
          'time.')
    elif jobs_allowlist:
      jobs_allowlist = [j.lower() for j in jobs_allowlist]
      for j in jobs_allowlist:
        if j not in registered_jobs:
          msg = 'Error allowlisting jobs: Job {0!s} is not found in registered jobs {1!s}.'.format(
              j, registered_jobs)
          raise TurbiniaException(msg)
      jobs_remove = [j for j in registered_jobs if j not in jobs_allowlist]
    elif jobs_denylist:
      jobs_denylist = [j.lower() for j in jobs_denylist]
      jobs_remove = [j for j in jobs_denylist if j in registered_jobs]

    # Deregister the jobs.
    jobs_remove = [j.lower() for j in jobs_remove]
    for job_name in jobs_remove:
      del cls._job_classes[job_name]

  @classmethod
  def GetJobInstance(cls, job_name):
    """Retrieves an instance of a specific job.

    Args:
      job_name (str): name of the job to retrieve.

    Returns:
      BaseJob: job instance.

    Raises:
      KeyError: if job class is not set for the corresponding name.
    """
    job_name = job_name.lower()
    if job_name not in cls._job_classes:
      raise KeyError('job class not set for name: {0:s}.'.format(job_name))

    job_class = cls._job_classes[job_name]
    return job_class()

  @classmethod
  def GetJobInstances(cls, job_names):
    """Retrieves instances for all the specified jobs.

    Args:
      job_names (list[str]): names of the jobs to retrieve.

    Returns:
      list[BaseJob]: job instances.
    """
    job_instances = []
    for job_name, job_class in iter(cls.GetJobs()):
      if job_name in job_names:
        job_instances.append(job_class())

    return job_instances

  @classmethod
  def GetJobNames(cls):
    """Retrieves the names of all loaded jobs.

    Returns:
      list[str]: of job names.
    """
    return cls._job_classes.keys()

  @classmethod
  def GetJobs(cls, job_names=None):
    """Retrieves the registered jobs.

    Args:
      job_names (list[str]): names of the jobs to retrieve.

    Yields:
      tuple: containing:

        str: the uniquely identifying name of the job
        type: the job class.
    """
    for job_name, job_class in iter(cls._job_classes.items()):
      if job_names:
        if job_name in job_names:
          yield job_name, job_class
      else:
        yield job_name, job_class

  @classmethod
  def RegisterJob(cls, job_class):
    """Registers a job class.

    The job classes are identified by their lower case name.

    Args:
      job_class (type): the job class to register.

    Raises:
      KeyError: if job class is already set for the corresponding name.
    """
    job_name = job_class.NAME.lower()
    if job_name in cls._job_classes:
      raise KeyError(
          'job class already set for name: {0:s}.'.format(job_class.NAME))

    cls._job_classes[job_name] = job_class

  @classmethod
  def RegisterJobs(cls, job_classes):
    """Registers a job class.

    The job classes are identified by their lower case name.

    Args:
      job_classes (list[type]): the job classes to register.

    Raises:
      KeyError: if job class is already set for the corresponding name.
    """
    for job_class in job_classes:
      cls.RegisterJob(job_class)

  @classmethod
  def RegisterDockerImage(cls, job_name, docker_image):
    """Registers a Docker image for the job.

    Args:
      job_name(str): name of the job.
      docker_image(str): name of the Docker image to be registered.
    """
    job_name = job_name.lower()
    cls._job_classes[job_name].docker_image = docker_image

  @classmethod
  def GetDockerImage(cls, job_name):
    """Retrieves the Docker image associated with the job.

    Args:
      job_name(str): name of the job.

    Returns:
      docker_image(str): The Docker image if available.
    """
    docker_image = None
    job_class = cls._job_classes.get(job_name.lower())
    if hasattr(job_class, 'docker_image') and job_class:
      docker_image = job_class.docker_image
    return docker_image

  @classmethod
  def RegisterTimeout(cls, job_name, timeout):
    """Registers a timeout for the job.

    Args:
      job_name(str): name of the job.
      timeout(int): The amount of seconds to wait before timing out.
    """
    job_name = job_name.lower()
    cls._job_classes[job_name].timeout = timeout

  @classmethod
  def GetTimeoutValue(cls, job_name):
    """Retrieves the timeout value associated with the job.

    Args:
      job_name(str): name of the job.

    Returns:
      timeout(int): The timeout value.
    """
    timeout = DEFAULT_TIMEOUT
    job_class = cls._job_classes.get(job_name.lower())
    if hasattr(job_class, 'timeout') and job_class:
      timeout = job_class.timeout
    return timeout
