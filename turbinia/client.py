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
import time

# TODO(aarontp): Selectively load dependencies based on configured backends
import psq

from turbinia import config
from turbinia.config import logger
from turbinia.lib.google_cloud import GoogleCloudFunction
from turbinia.state_manager import RedisStateManager
from turbinia import task_manager
from turbinia import TurbiniaException

log = logging.getLogger('turbinia')
logger.setup()


class TurbiniaClient(object):
  """Client class for Turbinia.

  Attributes:
    task_manager (TaskManager): Turbinia task manager
  """
  def __init__(self):
    config.LoadConfig()
    self.task_manager = task_manager.get_task_manager()
    self.task_manager.setup()

  def list_jobs(self):
    """List the available jobs."""
    log.info('Available Jobs:')
    for job in self.task_manager.jobs:
      log.info('\t{0:s}'.format(job.name))

  def wait_for_request(self, instance, project, region, request_id=None,
                       poll_interval=60):
    """Polls and waits for Turbinia Request to complete.

    Args:
      instance (string): The Turbinia instance name (by default the same as the
          PUBSUB_TOPIC in the config).
      project (string): The name of the project.
      region (string): The name of the region to execute in.
      request_id (string): The Id of the request we want tasks for.
      poll_interval (int): Interval of seconds between polling cycles.
    """
    while True:
      task_results = self.get_task_data(
          instance, project, region, request_id=request_id)
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


  def get_task_data(self, instance, project, region, days=0, task_id=None,
                    request_id=None, function_name='gettasks'):
    """Gets task data from Google Cloud Functions.

    Args:
      instance (string): The Turbinia instance name (by default the same as the
          PUBSUB_TOPIC in the config).
      project (string): The name of the project.
      region (string): The name of the region to execute in.
      days (int): The number of days we want history for.
      task_id (string): The Id of the task.
      request_id (string): The Id of the request we want tasks for.

    Returns:
      List of Task dict objects.
    """
    function = GoogleCloudFunction(project_id=project, region=region)
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

    response = function.ExecuteFunction(function_name, func_args)
    if not response.has_key('result'):
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


  def format_task_status(self, instance, project, region, days=0, task_id=None,
                         request_id=None, all_fields=False):
    """Formats the recent history for Turbinia Tasks.

    Args:
      instance (string): The Turbinia instance name (by default the same as the
          PUBSUB_TOPIC in the config).
      project (string): The name of the project.
      region (string): The name of the zone to execute in.
      days (int): The number of days we want history for.
      task_id (string): The Id of the task.
      request_id (string): The Id of the request we want tasks for.
      all_fields (bool): Include all fields for the task, including task,
          request ids and saved file paths.

    Returns: String of task status
    """
    task_results = self.get_task_data(instance, project, region, days, task_id,
                                      request_id)
    num_results = len(task_results)
    results = []
    if not num_results:
      msg = '\nNo Tasks found.'
      log.info(msg)
      return msg

    results.append('\nRetrieved {0:d} Task results:'.format(num_results))
    for task in task_results:
      if task.get('successful', None):
        success = 'Successful'
      elif task.get('successful', None) is None:
        success = 'Running'
      else:
        success = 'Failed'

      status = task.get('status') if task.get('status') else 'No task status'
      if all_fields:
        results.append(
            '{0:s} request: {1:s} task: {2:s} {3:s} {4:s} {5:s}: {6:s}'.format(
                task['last_update'], task['request_id'], task['id'],
                task['name'], task['worker_name'], success, status))
        saved_paths = task.get('saved_paths') if task.get('saved_paths') else []
        for path in saved_paths:
          results.append('\t{0:s}'.format(path))
      else:
        results.append('{0:s} {1:s} {2:s}: {3:s}'.format(
            task['last_update'], task['name'], success, status))

    return '\n'.join(results)

  def send_request(self, request):
    """Sends a TurbiniaRequest message.

    Args:
      request: A TurbiniaRequest object.
    """
    self.task_manager.server_pubsub.send_request(request)


class TurbiniaCeleryClient(TurbiniaClient):
  """Client class for Turbinia (Celery).

  Overriding some things specific to Celery operation.

  Attributes:
    redis (RedisStateManager): Redis datastore object
  """
  def __init__(self, *args, **kwargs):
    super(TurbiniaCeleryClient, self).__init__(*args, **kwargs)
    self.redis = RedisStateManager()

  def send_request(self, request):
    """Sends a TurbiniaRequest message.

    Args:
      request: A TurbiniaRequest object.
    """
    self.task_manager.kombu.send_request(request)

  def get_task_data(self, instance, _, __, days=0, task_id=None,
                    request_id=None, function_name='gettasks'):
    """Gets task data from Redis. We keep the same function signature,
        but ignore arguments passed for GCP.

    Args:
      instance (string): The Turbinia instance name (by default the same as the
          PUBSUB_TOPIC in the config).
      days (int): The number of days we want history for.
      task_id (string): The Id of the task.
      request_id (string): The Id of the request we want tasks for.

    Returns:
      List of Task dict objects.
    """
    return self.redis.get_task_data(instance, days, task_id, request_id)


class TurbiniaServer(TurbiniaClient):
  """Turbinia Server class."""
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
    super(TurbiniaCeleryWorker, self).__init__(*args, **kwargs)
    self.worker = self.task_manager.celery.app

  def start(self):
    """Start Turbinia Celery Worker."""
    log.info('Running Turbinia Celery Worker.')
    argv = [
        'celery',
        'worker',
        '--loglevel=info']
    self.worker.start(argv)


class TurbiniaPsqWorker(TurbiniaClient):
  """Turbinia PSQ Worker class.

  Attributes:
    worker (psq.Worker): PSQ Worker object
  """
  def __init__(self, *args, **kwargs):
    """Initialization for PSQ Worker."""
    super(TurbiniaPsqWorker, self).__init__(*args, **kwargs)
    log.info(
        'Starting PSQ listener on queue {0:s}'.format(
            self.task_manager.psq.name))
    self.worker = psq.Worker(queue=self.task_manager.psq)

  def start(self):
    """Start Turbinia PSQ Worker."""
    log.info('Running Turbinia PSQ Worker.')
    self.worker.listen()
