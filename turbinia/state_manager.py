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
"""State manager for Turbinia.

This handles management of task state and persists this information to Cloud
storage.
"""

from __future__ import unicode_literals

import codecs
import json
import logging
from datetime import datetime
from datetime import timedelta

import six

from turbinia import config
from turbinia.config import DATETIME_FORMAT
from turbinia import TurbiniaException
from turbinia.workers import TurbiniaTask
from turbinia.workers import TurbiniaTaskResult

config.LoadConfig()
if config.STATE_MANAGER.lower() == 'datastore':
  from google.cloud import datastore
  from google.cloud import exceptions
elif config.STATE_MANAGER.lower() == 'redis':
  import redis
else:
  msg = 'State Manager type "{0:s}" not implemented'.format(
      config.STATE_MANAGER)
  raise TurbiniaException(msg)

MAX_DATASTORE_STRLEN = 1500
log = logging.getLogger('turbinia')


def get_state_manager():
  """Return state manager object based on config.

  Returns:
    Initialized StateManager object.

  Raises:
    TurbiniaException: When an unknown State Manager is specified.
  """
  config.LoadConfig()
  # pylint: disable=no-else-return
  if config.STATE_MANAGER.lower() == 'datastore':
    return DatastoreStateManager()
  elif config.STATE_MANAGER.lower() == 'redis':
    return RedisStateManager()
  else:
    msg = 'State Manager type "{0:s}" not implemented'.format(
        config.STATE_MANAGER)
    raise TurbiniaException(msg)


class BaseStateManager(object):
  """Class to manage Turbinia state persistence."""

  def get_task_dict(self, task):
    """Creates a dict of the fields we want to persist into storage.

    This combines attributes from both the Task and the TaskResult into one flat
    object representing the overall state.

    Args:
      task: A TurbiniaTask object.

    Returns:
      A dict of task attributes.

    Raises:
      TurbiniaException: When task objects or task results are missing expected
          attributes
    """
    task_dict = {}
    for attr in task.STORED_ATTRIBUTES:
      if not hasattr(task, attr):
        raise TurbiniaException(
            'Task {0:s} does not have attribute {1:s}'.format(task.name, attr))
      task_dict[attr] = getattr(task, attr)
      if isinstance(task_dict[attr], six.binary_type):
        task_dict[attr] = codecs.decode(task_dict[attr], 'utf-8')

    if task.result:
      for attr in task.result.STORED_ATTRIBUTES:
        if not hasattr(task.result, attr):
          raise TurbiniaException(
              'Task {0:s} result does not have attribute {1:s}'.format(
                  task.name, attr))
        task_dict[attr] = getattr(task.result, attr)
        if isinstance(task_dict[attr], six.binary_type):
          task_dict[attr] = six.u(task_dict[attr])

    # We'll store the run_time as seconds instead of a timedelta()
    if task_dict.get('run_time'):
      task_dict['run_time'] = task_dict['run_time'].total_seconds()

    # Set all non-existent keys to None
    all_attrs = set(
        TurbiniaTask.STORED_ATTRIBUTES + TurbiniaTaskResult.STORED_ATTRIBUTES)
    task_dict.update({k: None for k in all_attrs if k not in task_dict})
    task_dict = self._validate_data(task_dict)

    # Using the pubsub topic as an instance attribute in order to have a unique
    # namespace per Turbinia installation.
    # TODO(aarontp): Migrate this to actual Datastore namespaces
    config.LoadConfig()
    task_dict.update({'instance': config.INSTANCE_ID})
    if isinstance(task_dict['instance'], six.binary_type):
      task_dict['instance'] = codecs.decode(task_dict['instance'], 'utf-8')
    return task_dict

  def _validate_data(self, data):
    """This validates the task dict before persisting into storage.

    Args:
      data (dict): The data we are going to send to Datastore.

    Returns:
      data (dict): The validated data
    """
    raise NotImplementedError

  def update_task(self, task):
    """Updates data for existing task.

    Args:
      task: A TurbiniaTask object
    """
    raise NotImplementedError

  def write_new_task(self, task):
    """Writes data for new task.

    Args:
      task: A TurbiniaTask object

    Returns:
      Key for written object
    """
    raise NotImplementedError


class DatastoreStateManager(BaseStateManager):
  """Datastore State Manager.

  Attributes:
    client: A Datastore client object.
  """

  def __init__(self):
    config.LoadConfig()
    try:
      self.client = datastore.Client(project=config.TURBINIA_PROJECT)
    except EnvironmentError as e:
      message = (
          'Could not create Datastore client: {0!s}\n'
          'Have you run $ gcloud auth application-default login?'.format(e))
      raise TurbiniaException(message)

  def _validate_data(self, data):
    for key, value in iter(data.items()):
      if (isinstance(value, six.string_types) and
          len(value) >= MAX_DATASTORE_STRLEN):
        log.warning(
            'Warning: key {0:s} with value {1:s} is longer than {2:d} bytes. '
            'Truncating in order to fit in Datastore.'.format(
                key, value, MAX_DATASTORE_STRLEN))
        suffix = '[...]'
        data[key] = value[:MAX_DATASTORE_STRLEN - len(suffix)] + suffix

    return data

  def update_task(self, task):
    task.touch()
    try:
      with self.client.transaction():
        entity = self.client.get(task.state_key)
        if not entity:
          self.write_new_task(task)
          return
        entity.update(self.get_task_dict(task))
        log.debug('Updating Task {0:s} in Datastore'.format(task.name))
        self.client.put(entity)
    except exceptions.GoogleCloudError as e:
      log.error(
          'Failed to update task {0:s} in datastore: {1!s}'.format(
              task.name, e))

  def write_new_task(self, task):
    key = self.client.key('TurbiniaTask', task.id)
    try:
      entity = datastore.Entity(key)
      entity.update(self.get_task_dict(task))
      log.info('Writing new task {0:s} into Datastore'.format(task.name))
      self.client.put(entity)
      task.state_key = key
    except exceptions.GoogleCloudError as e:
      log.error(
          'Failed to update task {0:s} in datastore: {1!s}'.format(
              task.name, e))
    return key


class RedisStateManager(BaseStateManager):
  """Use redis for task state storage.

  Attributes:
    client: Redis database object.
  """

  def __init__(self):
    config.LoadConfig()
    self.client = redis.StrictRedis(
        host=config.REDIS_HOST, port=config.REDIS_PORT, db=config.REDIS_DB)

  def _validate_data(self, data):
    return data

  def get_task_data(self, instance, days=0, task_id=None, request_id=None):
    """Gets task data from Redis.

    Args:
      instance (string): The Turbinia instance name (by default the same as the
          INSTANCE_ID in the config).
      days (int): The number of days we want history for.
      task_id (string): The Id of the task.
      request_id (string): The Id of the request we want tasks for.

    Returns:
      List of Task dict objects.
    """
    tasks = [
        json.loads(self.client.get(task))
        for task in self.client.scan_iter('TurbiniaTask:*')
        if json.loads(self.client.get(task)).get('instance') == instance or
        not instance
    ]

    # Convert relevant date attributes back into dates/timedeltas
    for task in tasks:
      if task.get('last_update'):
        task['last_update'] = datetime.strptime(
            task.get('last_update'), DATETIME_FORMAT)
      if task.get('run_time'):
        task['run_time'] = datetime.timedelta(seconds=task['run_time'])

    # pylint: disable=no-else-return
    if days:
      start_time = datetime.now() - timedelta(days=days)
      # Redis only supports strings; we convert to/from datetime here and below
      return [task for task in tasks if task.get('last_update') > start_time]
    elif task_id:
      return [task for task in tasks if task.get('task_id') == task_id]
    elif request_id:
      return [task for task in tasks if task.get('request_id') == request_id]
    return tasks

  def update_task(self, task):
    task.touch()
    key = task.state_key
    if not self.client.get(key):
      self.write_new_task(task)
      return
    log.info('Updating task {0:s} in Redis'.format(task.name))
    task_data = self.get_task_dict(task)
    task_data['last_update'] = task_data['last_update'].strftime(
        DATETIME_FORMAT)
    if task_data['run_time']:
      task_data['run_time'] = task_data['run_time'].total_seconds()
    # Need to use json.dumps, else redis returns single quoted string which
    # is invalid json
    if not self.client.set(key, json.dumps(task_data)):
      log.error(
          'Unsuccessful in updating task {0:s} in Redis'.format(task.name))

  def write_new_task(self, task):
    key = ':'.join(['TurbiniaTask', task.id])
    log.info('Writing new task {0:s} into Redis'.format(task.name))
    task_data = self.get_task_dict(task)
    task_data['last_update'] = task_data['last_update'].strftime(
        DATETIME_FORMAT)
    if task_data['run_time']:
      task_data['run_time'] = task_data['run_time'].total_seconds()
    # nx=True prevents overwriting (i.e. no unintentional task clobbering)
    if not self.client.set(key, json.dumps(task_data), nx=True):
      log.error(
          'Unsuccessful in writing new task {0:s} into Redis'.format(task.name))
    task.state_key = key
    return key
