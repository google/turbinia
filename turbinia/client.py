# -*- coding: utf-8 -*-
# Copyright 2017 Google Inc.
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

from __future__ import unicode_literals

from datetime import datetime
from datetime import timedelta
import json
import logging
import os
import stat
import time

from turbinia import config
from turbinia.config import logger
from turbinia import task_manager
from turbinia import TurbiniaException

config.LoadConfig()
if config.TASK_MANAGER == 'PSQ':
  import psq

  from google.cloud import exceptions
  from google.cloud import datastore
  from google.cloud import pubsub

  from turbinia.lib.google_cloud import GoogleCloudFunction
elif config.TASK_MANAGER == 'Celery':
  from turbinia.state_manager import RedisStateManager

log = logging.getLogger('turbinia')
logger.setup()


def check_directory(directory):
  """Checks directory to make sure it exists and is writable.

  Args:
    directory (string): Path to directory

  Raises:
    TurbiniaException: When directory cannot be created or used.
  """
  if os.path.exists(directory) and not os.path.isdir(directory):
    raise TurbiniaException(
        'File {0:s} exists, but is not a directory'.format(directory))

  if not os.path.exists(directory):
    try:
      os.makedirs(directory)
    except OSError:
      raise TurbiniaException(
          'Can not create Directory {0:s}'.format(directory))

  if not os.access(directory, os.W_OK):
    try:
      mode = os.stat(directory)[0]
      os.chmod(directory, mode | stat.S_IWUSR)
    except OSError:
      raise TurbiniaException(
          'Can not add write permissions to {0:s}'.format(directory))


class TurbiniaClient(object):
  """Client class for Turbinia.

  Attributes:
    task_manager (TaskManager): Turbinia task manager
  """

  def __init__(self):
    config.LoadConfig()
    self.task_manager = task_manager.get_task_manager()
    self.task_manager.setup(server=False)

  def list_jobs(self):
    """List the available jobs."""
    # TODO(aarontp): Refactor this out so that we don't need to depend on
    # the task manager from the client.
    log.info('Available Jobs:')
    for job in self.task_manager.jobs:
      log.info('\t{0:s}'.format(job.name))

  def wait_for_request(self,
                       instance,
                       project,
                       region,
                       request_id=None,
                       user=None,
                       poll_interval=60):
    """Polls and waits for Turbinia Request to complete.

    Args:
      instance (string): The Turbinia instance name (by default the same as the
          INSTANCE_ID in the config).
      project (string): The name of the project.
      region (string): The name of the region to execute in.
      request_id (string): The Id of the request we want tasks for.
      user (string): The user of the request we want tasks for.
      poll_interval (int): Interval of seconds between polling cycles.
    """
    while True:
      task_results = self.get_task_data(
          instance, project, region, request_id=request_id, user=user)
      completed_count = 0
      uncompleted_count = 0
      for task in task_results:
        if task.get('successful') is not None:
          completed_count += 1
        else:
          uncompleted_count += 1

      if completed_count and completed_count == len(task_results):
        break

      log.info(
          '{0:d} Tasks found, {1:d} completed. Waiting {2:d} seconds.'.format(
              len(task_results), completed_count, poll_interval))
      time.sleep(poll_interval)

    log.info('All {0:d} Tasks completed'.format(len(task_results)))

  def get_task_data(self,
                    instance,
                    project,
                    region,
                    days=0,
                    task_id=None,
                    request_id=None,
                    user=None,
                    function_name='gettasks'):
    """Gets task data from Google Cloud Functions.

    Args:
      instance (string): The Turbinia instance name (by default the same as the
          INSTANCE_ID in the config).
      project (string): The name of the project.
      region (string): The name of the region to execute in.
      days (int): The number of days we want history for.
      task_id (string): The Id of the task.
      request_id (string): The Id of the request we want tasks for.
      user (string): The user of the request we want tasks for.
      function_name (string): The GCF function we want to call

    Returns:
      List of Task dict objects.
    """
    cloud_function = GoogleCloudFunction(project_id=project, region=region)
    func_args = {'instance': instance, 'kind': 'TurbiniaTask'}

    if days:
      start_time = datetime.now() - timedelta(days=days)
      # Format this like '1990-01-01T00:00:00z' so we can cast it directly to a
      # javascript Date() object in the cloud function.
      start_string = start_time.strftime('%Y-%m-%dT%H:%M:%S')
      func_args.update({'start_time': start_string})
    elif task_id:
      func_args.update({'task_id': task_id})
    elif request_id:
      func_args.update({'request_id': request_id})

    if user:
      func_args.update({'user': user})

    response = cloud_function.ExecuteFunction(function_name, func_args)
    if 'result' not in response:
      log.error('No results found')
      if response.get('error', '{}') != '{}':
        msg = 'Error executing Cloud Function: [{0!s}].'.format(
            response.get('error'))
        log.error(msg)
      log.debug('GCF response: {0!s}'.format(response))
      raise TurbiniaException(
          'Cloud Function {0:s} returned no results.'.format(function_name))

    try:
      results = json.loads(response['result'])
    except (TypeError, ValueError) as e:
      raise TurbiniaException(
          'Could not deserialize result from GCF: [{0!s}]'.format(e))

    return results[0]

  def format_task_status(self,
                         instance,
                         project,
                         region,
                         days=0,
                         task_id=None,
                         request_id=None,
                         user=None,
                         all_fields=False):
    """Formats the recent history for Turbinia Tasks.

    Args:
      instance (string): The Turbinia instance name (by default the same as the
          INSTANCE_ID in the config).
      project (string): The name of the project.
      region (string): The name of the zone to execute in.
      days (int): The number of days we want history for.
      task_id (string): The Id of the task.
      request_id (string): The Id of the request we want tasks for.
      user (string): The user of the request we want tasks for.
      all_fields (bool): Include all fields for the task, including task,
          request ids and saved file paths.

    Returns:
      String of task status
    """
    task_results = self.get_task_data(instance, project, region, days, task_id,
                                      request_id, user)
    num_results = len(task_results)
    results = []
    if not num_results:
      msg = '\nNo Tasks found.'
      log.info(msg)
      return msg

    results.append('\nRetrieved {0:d} Task results:'.format(num_results))
    for task in task_results:
      if task.get('successful'):
        success = 'Successful'
      elif task.get('successful') is None:
        success = 'Running'
      else:
        success = 'Failed'

      status = task.get('status', 'No task status')
      if all_fields:
        results.append(
            '{0:s} request: {1:s} task: {2:s} {3:s} {4:s} {5:s} {6:s}: {7:s}'.
            format(
                task.get('last_update'), task.get('request_id'), task.get('id'),
                task.get('name'), task.get('user'), task.get('worker_name'),
                success, status))
        saved_paths = task.get('saved_paths', [])
        if saved_paths is None:
          saved_paths = []
        for path in saved_paths:
          results.append('\t{0:s}'.format(path))
      else:
        results.append('{0:s} {1:s} {2:s}: {3:s}'.format(
            task.get('last_update'), task.get('name'), success, status))

    return '\n'.join(results)

  def send_request(self, request):
    """Sends a TurbiniaRequest message.

    Args:
      request: A TurbiniaRequest object.
    """
    self.task_manager.server_pubsub.send_request(request)

  def close_tasks(self,
                  instance,
                  project,
                  region,
                  request_id=None,
                  task_id=None,
                  user=None,
                  requester=None):
    """Close Turbinia Tasks based on Request ID.

    Args:
      instance (string): The Turbinia instance name (by default the same as the
          INSTANCE_ID in the config).
      project (string): The name of the project.
      region (string): The name of the zone to execute in.
      request_id (string): The Id of the request we want tasks for.
      task_id (string): The Id of the request we want task for.
      user (string): The user of the request we want tasks for.
      requester (string): The user making the request to close tasks.

    Returns: String of closed Task IDs.
    """
    cloud_function = GoogleCloudFunction(project_id=project, region=region)
    func_args = {
        'instance': instance,
        'kind': 'TurbiniaTask',
        'request_id': request_id,
        'task_id': task_id,
        'user': user,
        'requester': requester
    }
    response = cloud_function.ExecuteFunction('closetasks', func_args)
    return 'Closed Task IDs: %s' % response.get('result')


class TurbiniaCeleryClient(TurbiniaClient):
  """Client class for Turbinia (Celery).

  Overriding some things specific to Celery operation.

  Attributes:
    redis (RedisStateManager): Redis datastore object
  """

  def __init__(self, *args, **kwargs):
    super(TurbiniaCeleryClient, self).__init__()
    self.redis = RedisStateManager()

  def send_request(self, request):
    """Sends a TurbiniaRequest message.

    Args:
      request: A TurbiniaRequest object.
    """
    self.task_manager.kombu.send_request(request)

  # pylint: disable=arguments-differ
  def get_task_data(self,
                    instance,
                    _,
                    __,
                    days=0,
                    task_id=None,
                    request_id=None,
                    function_name=None):
    """Gets task data from Redis.

    We keep the same function signature, but ignore arguments passed for GCP.

    Args:
      instance (string): The Turbinia instance name (by default the same as the
          INSTANCE_ID in the config).
      days (int): The number of days we want history for.
      task_id (string): The Id of the task.
      request_id (string): The Id of the request we want tasks for.

    Returns:
      List of Task dict objects.
    """
    return self.redis.get_task_data(instance, days, task_id, request_id)


class TurbiniaServer(object):
  """Turbinia Server class.

  Attributes:
    task_manager (TaskManager): An object to manage turbinia tasks.
  """

  def __init__(self):
    """Initialize Turbinia Server."""
    config.LoadConfig()
    self.task_manager = task_manager.get_task_manager()
    self.task_manager.setup()

  def start(self):
    """Start Turbinia Server."""
    log.info('Running Turbinia Server.')
    self.task_manager.run()

  def add_evidence(self, evidence_):
    """Add evidence to be processed."""
    self.task_manager.add_evidence(evidence_)


class TurbiniaCeleryWorker(TurbiniaClient):
  """Turbinia Celery Worker class.

  Attributes:
    worker (celery.app): Celery worker app
  """

  def __init__(self, *args, **kwargs):
    """Initialization for Celery worker."""
    super(TurbiniaCeleryWorker, self).__init__()
    check_directory(config.MOUNT_DIR_PREFIX)
    check_directory(config.OUTPUT_DIR)
    self.worker = self.task_manager.celery.app

  def start(self):
    """Start Turbinia Celery Worker."""
    log.info('Running Turbinia Celery Worker.')
    argv = ['celery', 'worker', '--loglevel=info']
    self.worker.start(argv)


class TurbiniaPsqWorker(object):
  """Turbinia PSQ Worker class.

  Attributes:
    worker (psq.Worker): PSQ Worker object
    psq (psq.Queue): A Task queue object

  Raises:
    TurbiniaException: When errors occur
  """

  def __init__(self, *_, **__):
    """Initialization for PSQ Worker."""
    config.LoadConfig()
    psq_publisher = pubsub.PublisherClient()
    psq_subscriber = pubsub.SubscriberClient()
    datastore_client = datastore.Client(project=config.PROJECT)
    try:
      self.psq = psq.Queue(
          psq_publisher,
          psq_subscriber,
          config.PROJECT,
          name=config.PSQ_TOPIC,
          storage=psq.DatastoreStorage(datastore_client))
    except exceptions.GoogleCloudError as e:
      msg = 'Error creating PSQ Queue: {0:s}'.format(str(e))
      log.error(msg)
      raise TurbiniaException(msg)

    check_directory(config.MOUNT_DIR_PREFIX)
    check_directory(config.OUTPUT_DIR)

    log.info('Starting PSQ listener on queue {0:s}'.format(self.psq.name))
    self.worker = psq.Worker(queue=self.psq)

  def start(self):
    """Start Turbinia PSQ Worker."""
    log.info('Running Turbinia PSQ Worker.')
    self.worker.listen()
