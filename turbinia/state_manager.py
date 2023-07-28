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
import sys
from datetime import datetime
from datetime import timedelta
from typing import Any

import six

from turbinia import config
from turbinia.config import DATETIME_FORMAT
from turbinia import TurbiniaException

config.LoadConfig()
if 'unittest' in sys.modules.keys():
  from google.cloud import datastore
  from google.cloud import exceptions
  from google.auth import exceptions as auth_exceptions
  import redis

if config.STATE_MANAGER.lower() == 'datastore':
  from google.cloud import datastore
  from google.cloud import exceptions
  from google.auth import exceptions as auth_exceptions
elif config.STATE_MANAGER.lower() == 'redis':
  import redis
else:
  msg = f'State Manager type "{config.STATE_MANAGER:s}" not implemented'
  raise TurbiniaException(msg)

IMPORTANT_ATTRIBUTES = (
    'hash', 'id', 'type', 'source_path', 'local_path', 'mount_path', 'size',
    'source')
MAX_DATASTORE_STRLEN = 1500
log = logging.getLogger('turbinia')


class Evidence:
  pass


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
    msg = f'State Manager type "{config.STATE_MANAGER:s}" not implemented'
    raise TurbiniaException(msg)


class BaseStateManager:
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
            f'Task {task.name:s} does not have attribute {attr:s}')
      task_dict[attr] = getattr(task, attr)
      if isinstance(task_dict[attr], six.binary_type):
        task_dict[attr] = codecs.decode(task_dict[attr], 'utf-8')

    if task.result:
      for attr in task.result.STORED_ATTRIBUTES:
        if not hasattr(task.result, attr):
          raise TurbiniaException(
              f'Task {task.name:s} result does not have attribute {attr:s}')
        task_dict[attr] = getattr(task.result, attr)
        if isinstance(task_dict[attr], six.binary_type):
          task_dict[attr] = six.u(task_dict[attr])

    # We'll store the run_time as seconds instead of a timedelta()
    if task_dict.get('run_time'):
      task_dict['run_time'] = task_dict['run_time'].total_seconds()

    #Importing these here to avoid circular dependencies.
    from turbinia.workers import TurbiniaTask
    from turbinia.workers import TurbiniaTaskResult
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
    except (EnvironmentError,
            auth_exceptions.DefaultCredentialsError) as exception:
      message = (
          'Could not create Datastore client: {0!s}\n'
          'Have you run $ gcloud auth application-default login?'.format(
              exception))
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
        if not task.state_key:
          self.write_new_task(task)
          return
        entity = self.client.get(task.state_key)
        entity.update(self.get_task_dict(task))
        log.debug(f'Updating Task {task.name:s} in Datastore')
        self.client.put(entity)
    except exceptions.GoogleCloudError as exception:
      log.error(
          f'Failed to update task {task.name:s} in datastore: {exception!s}')

  def write_new_task(self, task):
    key = self.client.key('TurbiniaTask', task.id)
    try:
      entity = datastore.Entity(key)
      task_data = self.get_task_dict(task)
      if not task_data.get('status'):
        task_data['status'] = 'Task scheduled at {0:s}'.format(
            datetime.now().strftime(DATETIME_FORMAT))
      entity.update(task_data)
      log.info(f'Writing new task {task.name:s} into Datastore')
      self.client.put(entity)
      task.state_key = key
    except exceptions.GoogleCloudError as exception:
      log.error(
          f'Failed to update task {task.name:s} in datastore: {exception!s}')
    return key


class RedisStateManager(BaseStateManager):
  """Use redis for task state storage.

  Attributes:
    client: Redis database object.
  """

  def __init__(self):
    config.LoadConfig()
    self.client = redis.StrictRedis(
        host=config.REDIS_HOST, port=config.REDIS_PORT, db=config.REDIS_DB,
        socket_timeout=10, socket_keepalive=True, socket_connect_timeout=10)

  def _validate_data(self, data):
    return data

  def get_task_data(
      self, instance, days=0, task_id=None, request_id=None, group_id=None,
      user=None):
    """Gets task data from Redis.

    Args:
      instance (string): The Turbinia instance name (by default the same as the
          INSTANCE_ID in the config).
      days (int): The number of days we want history for.
      task_id (string): The Id of the task.
      request_id (string): The Id of the request we want tasks for.
      group_id (string): Group Id of the requests.
      user (string): The user of the request we want tasks for.

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
        task['run_time'] = timedelta(seconds=task['run_time'])

    # pylint: disable=no-else-return
    if days:
      start_time = datetime.now() - timedelta(days=days)
      # Redis only supports strings; we convert to/from datetime here and below
      tasks = [task for task in tasks if task.get('last_update') > start_time]
    if task_id:
      tasks = [task for task in tasks if task.get('id') == task_id]
    if request_id:
      tasks = [task for task in tasks if task.get('request_id') == request_id]
    if group_id:
      tasks = [task for task in tasks if task.get('group_id') == group_id]
    if user:
      tasks = [task for task in tasks if task.get('requester') == user]

    return tasks

  def update_task(self, task):
    task.touch()
    key = task.state_key
    if not key:
      self.write_new_task(task)
      return
    stored_task_data = json.loads(self.client.get(f'TurbiniaTask:{task.id}'))
    stored_evidence_size = stored_task_data.get('evidence_size')
    stored_evidence_id = stored_task_data.get('evidence_id')
    if not task.evidence_size and stored_evidence_size:
      task.evidence_size = stored_evidence_size
    if not task.evidence_ids and stored_evidence_id:
      task.evidence_ids = stored_evidence_id
    log.info(f'Updating task {task.name:s} in Redis')
    task_data = self.get_task_dict(task)
    task_data['last_update'] = task_data['last_update'].strftime(
        DATETIME_FORMAT)
    # Need to use json.dumps, else redis returns single quoted string which
    # is invalid json
    if not self.client.set(key, json.dumps(task_data)):
      log.error(f'Unsuccessful in updating task {task.name:s} in Redis')

  def write_new_task(self, task):
    key = ':'.join(('TurbiniaTask', task.id))
    log.info(f'Writing new task {task.name:s} into Redis')
    task_data = self.get_task_dict(task)
    task_data['last_update'] = task_data['last_update'].strftime(
        DATETIME_FORMAT)
    if not task_data.get('status'):
      task_data['status'] = 'Task scheduled at {0:s}'.format(
          datetime.now().strftime(DATETIME_FORMAT))
    if task_data['run_time']:
      task_data['run_time'] = task_data['run_time'].total_seconds()
    # nx=True prevents overwriting (i.e. no unintentional task clobbering)
    if not self.client.set(key, json.dumps(task_data), nx=True):
      log.error(f'Unsuccessful in writing new task {task.name:s} into Redis')
    task.state_key = key
    return key

  def write_new_evidence(self, evidence: Evidence):
    """Writes a new evidence into redis.

    Args:
      evidence (Evidence): The evidence that will be saved.

    Returns:
      key (str): The key corresponding to the evidence in redis
    """
    if not (hasattr(evidence, 'id') and evidence.id):
      error_message = ', '.join((
          f'Unsuccessful in writing evidence {evidence.name} into Redis',
          'evidence has no id'))
      log.error(error_message)
      raise AttributeError(error_message)
    if hasattr(evidence, 'type') and evidence.type:
      key = ':'.join(('TurbiniaEvidence', evidence.id))
      log.info(f'Writing new evidence {evidence.id:s} into Redis')
      for attribute_key, attribute_value in evidence.__dict__.items():
        try:
          if not self.client.hset(key, attribute_key,
                                  json.dumps(attribute_value)):
            log.error(
                f'Unsuccessful in writing evidence {evidence.id} into Redis')
        except (TypeError, OverflowError):
          log.error(
              f'Attribute {attribute_key} in {evidence.id} is not serializable')
      self.client.sadd('TurbiniaEvidenceCollection', key)
      if evidence.hash:
        key = self.client.hset('TurbiniaEvidenceHashes', evidence.hash, key)
      return key

  def update_evidence_attribute(self, evidence_id: str, name: str, value: Any):
    """Updates one attribute of the evidence in Redis.

    Args:
      evidence_id (str): The ID of the stored evidence.
      name (str): name of the attribute to be updated.
      value (Any): value to be updated.
    
    Raises:
      TypeError, OverflowError: Value is not Json Serializable. 
    """
    key = ':'.join(('TurbiniaEvidence', evidence_id))
    message = f'attribute {name} for evidence {value} in Redis'
    log.info(f'Updating {message}')
    try:
      if self.client.hset(key, name, json.dumps(value)):
        if name == 'hash' and value:
          key = self.client.hset('TurbiniaEvidenceHashes', value, key)
        if name == 'request_id':
          requests = json.loads(self.client.hget(key, 'previuos_requests'))
          if value not in requests:
            requests.append(value)
            self.client.hset(key, 'previuos_requests', json.dumps(requests))
    except (TypeError, OverflowError) as exception:
      log.error(f'Attribute {name} in {evidence_id} is not serializable')
      raise exception

  def get_evidence(self, evidence_id: str):
    """Gets one evidence from Redis given its ID.

    Args:
      evidence_id (str): The ID of the stored evidence.

    Returns:
      evidence_dict (dict): Dict containing evidence attributes. 
    """
    key = ':'.join(('TurbiniaEvidence', evidence_id))
    evidence_keys = self.client.hkeys(key)
    evidence_dict = {}
    for attribute_key in evidence_keys:
      evidence_dict[attribute_key.decode()] = json.loads(
          self.client.hget(key, attribute_key))
    return evidence_dict

  def evidence_exists(self, evidence_id):
    """Checks if the evidence is saved in Redis given its ID.

    Args:
      evidence_id (str): The ID of the stored evidence.

    Returns:
      evidence_id (bool): Boolean indicating if evidence is saved. 
    """
    return self.client.exists(':'.join(('TurbiniaEvidence', evidence_id)))

  def get_evidence_summary(self):
    """Gets a summary of all evidences.

    Returns:
      summary (dict): Dict containing evidences of each type. 
    """
    summary = {}
    for key in self.client.smembers('TurbiniaEvidenceCollection'):
      value = self.get_evidence(key.decode().split(':')[1])
      evidence_type = value.get('type', 'Evidence')
      if evidence_type not in summary:
        summary[evidence_type] = {}
      summary[evidence_type][key.decode()] = value
    return summary

  def get_evidence_key_by_hash(self, file_hash: str):
    """Gets the evidence key given its hash.

    Args:
      file_hash (str): The hash of the stored evidence.

    Returns:
      key (str): Key of the stored evidence. 
    """
    if file_hash:
      key = self.client.hget('TurbiniaEvidenceHashes', file_hash)
      if key:
        return key.decode()

  def get_evidence_by_hash(self, file_hash: str):
    """Gets the evidence given its hash.

    Args:
      file_hash (str): The hash of the stored evidence.

    Returns:
      evidence_dict (dict): Dict containing evidence attributes. 
    """
    evidence_id = self.get_evidence_key_by_hash(file_hash).split(':')[1]
    return self.get_evidence(evidence_id)

  def get_evidence_by_attributes(self, evidence: Evidence):
    """Gets the evidence given its hash. 

    Args:
      file_hash (str): The hash of the stored evidence.

    Returns:
      evidence_dict (dict): Dict containing evidence attributes. 
    """
    for key in self.client.smembers('TurbiniaEvidenceCollection'):
      equal = True
      for attribute in IMPORTANT_ATTRIBUTES:
        if attribute in evidence.__dict__ and evidence.__dict__[
            attribute] != json.loads(self.client.hget(key, attribute)):
          equal = False
          break
      if equal:
        return key.decode()
