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
"""Client objects for Turbinia."""

import logging
import os
import stat
import subprocess

from prometheus_client import start_http_server
from turbinia import config
from turbinia.config import logger
from turbinia import task_utils
from turbinia import TurbiniaException
from turbinia import job_utils
from turbinia.lib import docker_manager
from turbinia.jobs import manager as job_manager
from turbinia.tcelery import TurbiniaCelery

config.LoadConfig()
task_manager_type = config.TASK_MANAGER.lower()
if task_manager_type == 'celery':
  from turbinia import tcelery as turbinia_celery
else:
  raise TurbiniaException(
      'Unknown task manager {0:s} found, please update config to use "Celery"'
      .format(task_manager_type))

log = logging.getLogger('turbinia')


def setup(is_client=False):
  config.LoadConfig()
  if is_client:
    logger.setup(need_file_handler=False)
  else:
    logger.setup()


def check_docker_dependencies(dependencies):
  """Checks docker dependencies.

  Args:
    dependencies(dict): dictionary of dependencies to check for.

  Raises:
    TurbiniaException: If dependency is not met.
  """
  #TODO(wyassine): may run into issues down the line when a docker image
  # does not have bash or which installed. (no linux fs layer).
  log.info('Performing docker dependency check.')
  job_names = list(job_manager.JobsManager.GetJobNames())

  # Iterate through list of jobs
  for job, values in dependencies.items():
    if job not in job_names:
      log.warning(
          'The job {0:s} was not found or has been disabled. Skipping '
          'dependency check...'.format(job))
      continue

    for program in values['programs']:
      docker_image = values.get('docker_image')
      if (config.DOCKER_ENABLED and docker_image is not None):
        log.info(
            'docker_image({0:s}): {1:s} program: {2:s}'.format(
                job, values['docker_image'], program))
        # Check if docker_image exists in registry.
        exists = docker_manager.DockerManager().image_exists(docker_image)
        if not exists:
          raise TurbiniaException(
              'Docker image {0:s} does not exist for the job {1:s}. Please '
              'update the config with the correct image name'.format(
                  values['docker_image'], job))
        # # Check if job program exists in docker image.
        # # Comment out this part if you want to verify the command in all
        # # job docker images. Note: This will download *all* docker images
        # # each time a worker is started.
        # cmd = f'type {program:s}'
        # stdout, stderr, ret = docker_manager.ContainerManager(
        #     values['docker_image']).execute_container(cmd, shell=True)
        # if ret != 0:
        #   raise TurbiniaException(
        #       'Job dependency {0:s} not found for job {1:s}. Please install '
        #       'the dependency for the container or disable the job.'.format(
        #           program, job))
        job_manager.JobsManager.RegisterDockerImage(job, values['docker_image'])


def check_system_dependencies(dependencies):
  """Checks system dependencies.

  Args:
    dependencies(dict): dictionary of dependencies to check for.

  Raises:
    TurbiniaException: If dependency is not met.
  """
  log.info('Performing system dependency check.')
  job_names = list(job_manager.JobsManager.GetJobNames())

  # Iterate through list of jobs
  for job, values in dependencies.items():
    if job not in job_names:
      log.warning(
          'The job {0:s} was not found or has been disabled. Skipping '
          'dependency check...'.format(job))
      continue
    elif not values.get('docker_image'):
      for program in values['programs']:
        cmd = f'type {program:s}'
        proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
        output, _ = proc.communicate()
        log.debug(f"Dependency resolved: {output.strip().decode('utf8'):s}")
        ret = proc.returncode
        if ret != 0:
          raise TurbiniaException(
              'Job dependency {0:s} not found in $PATH for the job {1:s}. '
              'Please install the dependency or disable the job.'.format(
                  program, job))


def check_directory(directory):
  """Checks directory to make sure it exists and is writable.

  Args:
    directory (string): Path to directory

  Raises:
    TurbiniaException: When directory cannot be created or used.
  """
  if os.path.exists(directory) and not os.path.isdir(directory):
    raise TurbiniaException(
        f'File {directory:s} exists, but is not a directory')

  if not os.path.exists(directory):
    try:
      os.makedirs(directory)
    except OSError:
      raise TurbiniaException(f'Can not create Directory {directory:s}')

  if not os.access(directory, os.W_OK):
    try:
      mode = os.stat(directory)[0]
      os.chmod(directory, mode | stat.S_IWUSR)
    except OSError:
      raise TurbiniaException(f'Can not add write permissions to {directory:s}')


class TurbiniaWorkerBase:
  """Base class for Turibinia Workers."""

  def __init__(self, jobs_denylist=None, jobs_allowlist=None):
    """Initialization for Turbinia Worker.

    Args:
      jobs_denylist (Optional[list[str]]): Jobs we will exclude from running
      jobs_allowlist (Optional[list[str]]): The only Jobs we will include to run
    """
    setup()
    # Deregister jobs from denylist/allowlist.
    job_manager.JobsManager.DeregisterJobs(jobs_denylist, jobs_allowlist)
    disabled_jobs = list(config.DISABLED_JOBS) if config.DISABLED_JOBS else []
    disabled_jobs = [j.lower() for j in disabled_jobs]
    # Only actually disable jobs that have not been allowlisted.
    if jobs_allowlist:
      disabled_jobs = list(set(disabled_jobs) - set(jobs_allowlist))
    if disabled_jobs:
      log.info(
          'Disabling non-allowlisted jobs configured to be disabled in the '
          'config file: {0:s}'.format(', '.join(disabled_jobs)))
      job_manager.JobsManager.DeregisterJobs(jobs_denylist=disabled_jobs)

    # Check for valid dependencies/directories.
    dependencies = config.ParseDependencies()
    if config.DOCKER_ENABLED:
      try:
        check_docker_dependencies(dependencies)
      except TurbiniaException as exception:
        log.warning(
            "DOCKER_ENABLED=True is set in the config, but there is an error checking for the docker daemon: {0:s}"
        ).format(str(exception))
    check_system_dependencies(dependencies)
    check_directory(config.MOUNT_DIR_PREFIX)
    check_directory(config.OUTPUT_DIR)
    check_directory(config.TMP_DIR)
    job_utils.register_job_timeouts(dependencies)

    jobs = job_manager.JobsManager.GetJobNames()
    log.info(
        'Dependency check complete. The following jobs are enabled '
        'for this worker: {0:s}'.format(','.join(jobs)))

  def _monitoring_setup(self):
    """Sets up monitoring server."""
    if config.PROMETHEUS_ENABLED:
      if config.PROMETHEUS_PORT and config.PROMETHEUS_ADDR:
        log.info('Starting Prometheus endpoint.')
        start_http_server(
            port=config.PROMETHEUS_PORT, addr=config.PROMETHEUS_ADDR)
      else:
        log.info('Prometheus enabled but port or address not set!')

  def _backend_setup(self):
    """Sets up the required backend dependencies for the worker"""
    raise NotImplementedError

  def start(self):
    """Start Turbinia Worker."""
    raise NotImplementedError


class TurbiniaCeleryWorker(TurbiniaWorkerBase):
  """Turbinia Celery Worker class.

  Attributes:
    worker (celery.app): Celery worker app
    celery (TurbiniaCelery): Turbinia Celery object
  """

  def __init__(self, *args, **kwargs):
    super(TurbiniaCeleryWorker, self).__init__(*args, **kwargs)
    self.worker = None
    self.celery = None

  def _backend_setup(self):
    self.celery = turbinia_celery.TurbiniaCelery()
    self.celery.setup()
    self.worker = self.celery.app

  def start(self):
    """Start Turbinia Celery Worker."""
    log.info('Running Turbinia Celery Worker.')
    self._monitoring_setup()
    self._backend_setup()
    # Disable worker ping checks per amount of signals these generate,
    # no apparent benefit from having this enabled at the moment.
    self.worker.task(task_utils.task_runner, name='task_runner')
    argv = [
        'worker', '--loglevel=info', '--concurrency=1', '--without-gossip',
        '--without-mingle'
    ]
    self.worker.start(argv)
