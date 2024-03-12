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
from typing import Any, Iterator

import six

from turbinia import config
from turbinia.config import DATETIME_FORMAT
from turbinia import TurbiniaException

config.LoadConfig()
if 'unittest' in sys.modules.keys():
  from google.auth import exceptions as auth_exceptions
  import redis

if config.STATE_MANAGER.lower() == 'redis':
  import redis
else:
  msg = f'State Manager type "{config.STATE_MANAGER:s}" not implemented'
  raise TurbiniaException(msg)

EMPTY_JSON_VALUES = ('null', '{}', '[]')
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
  if config.STATE_MANAGER.lower() == 'redis':
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

  def set_client(self, redis_client):
    self.client = redis_client

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
        for task in self.client.scan_iter(match='TurbiniaTask:*', count=1000)
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
    if not task.evidence_id and stored_evidence_id:
      task.evidence_id = stored_evidence_id
    log.info(f'Updating task {task.name:s} in Redis')
    task_data = self.get_task_dict(task)
    task_data['last_update'] = task_data['last_update'].strftime(
        DATETIME_FORMAT)
    task_data['start_time'] = task_data['start_time'].strftime(DATETIME_FORMAT)
    # Need to use json.dumps, else redis returns single quoted string which
    # is invalid json
    if not self.client.set(key, json.dumps(task_data)):
      log.error(f'Error updating task {task.name:s} in Redis')

  def write_new_task(self, task):
    key = ':'.join(['TurbiniaTask', task.id])
    log.info(f'Writing new task {task.name:s} into Redis')
    task_data = self.get_task_dict(task)
    task_data['last_update'] = task_data['last_update'].strftime(
        DATETIME_FORMAT)
    task_data['start_time'] = task_data['start_time'].strftime(DATETIME_FORMAT)
    if not task_data.get('status'):
      task_data['status'] = 'Task scheduled at {0:s}'.format(
          datetime.now().strftime(DATETIME_FORMAT))
    if task_data['run_time']:
      task_data['run_time'] = task_data['run_time'].total_seconds()
    # nx=True prevents overwriting (i.e. no unintentional task clobbering)
    if not self.client.set(key, json.dumps(task_data), nx=True):
      log.error(f'Error writing new task {task.name:s} into Redis')
    task.state_key = key
    return key

  def set_attribute(
      self, redis_key: str, attribute_name: str, json_value: str) -> bool:
    """Sets the attribute of a Turbinia hash object in redis.

    Args:
      redis_key (str): The key of the Turbinia hash object in redis.
      attribute_name (str): The name of the attribute to be set.
      json_value (str): The json-serialized value to be set

    Returns:
      (bool): Boolean specifying whether the function call was successful. 

    Raises:
      TurbiniaException: When Redis fails in updating the attribute.
    """
    try:
      if not self.client.hset(redis_key, attribute_name, json_value):
        log.error(f'Error setting {attribute_name} on {redis_key} in Redis')
        return False
      return True
    except redis.RedisError as exception:
      error_message = (
          f'Error setting {attribute_name} on {redis_key} in Redis')
      log.error(f'{error_message}: {exception}')
      raise TurbiniaException(error_message) from exception

  def get_attribute(
      self, redis_key: str, attribute_name: str,
      decode_json: bool = True) -> Any:
    """Gets the attribute of a Turbinia hash object in redis.

    Args:
      redis_key (str): The key of the Turbinia hash object in redis.
      attribute_name (str): The name of the attribute to be get.
      decode_json (bool): Boolean specifying if the value should be loaded.

    Returns:
      attribute_value (any): successful. 

    Raises:
      TurbiniaException: If Redis fails in getting the attribute or if
        json loads fails.
    """
    try:
      attribute_value = self.client.hget(redis_key, attribute_name)
    except redis.RedisError as exception:
      error_message = (
          f'Error getting {attribute_name} from {redis_key} in Redis')
      log.error(f'{error_message}: {exception}')
      raise TurbiniaException(error_message) from exception
    if decode_json:
      try:
        return json.loads(attribute_value)
      except (TypeError, ValueError) as exception:
        error_message = (
            f'Error decoding JSON {attribute_name} on {redis_key} '
            f'in Redis')
        log.error(f'{error_message}: {exception}')
        raise TurbiniaException(error_message) from exception
    else:
      return attribute_value

  def iterate_keys(self, key_type: str) -> Iterator[str]:
    """Iterates over the Turbinia keys of a specific type.

    Args:
      key_type (str): The type of the Turbinia key (e.g. Task, Evidence)

    Yields:
      key (str): Decoded key of stored Turbinia object. 

    Raises:
      TurbiniaException: If Redis fails in getting the keys or if
        decode fails.
    """
    try:
      keys = self.client.scan_iter(f'Turbinia{key_type.title()}:*', count=1000)
    except redis.RedisError as exception:
      error_message = f'Error getting {key_type} keys in Redis'
      log.error(f'{error_message}: {exception}')
      raise TurbiniaException(error_message) from exception
    try:
      for key in keys:
        yield key.decode()
    except ValueError as exception:
      error_message = 'Error decoding key in Redis'
      log.error(f'{error_message}: {exception}')
      raise TurbiniaException(error_message) from exception

  def iterate_attributes(self, key: str) -> Iterator[tuple]:
    """Iterates over the attribute names of the Redis hash object.

    Args:
      key (str): The key of the stored hash object.

    Yields:
      attribute_name (tuple): Decoded name of object attribute.

    Raises:
      TurbiniaException: If Redis fails in getting the attributes or if
        decode or json loads fails. 
    """
    try:
      attributes = self.client.hscan_iter(key, count=100)
    except redis.RedisError as exception:
      error_message = f'Error getting attributes from {key} in Redis'
      log.error(f'{error_message}: {exception}')
      raise TurbiniaException(error_message) from exception
    try:
      for attribute in attributes:
        yield (attribute[0].decode(), json.loads(attribute[1]))
    except (TypeError, ValueError) as exception:
      error_message = f'Error decoding attribute in {key} in Redis'
      log.error(f'{error_message}: {exception}')
      raise TurbiniaException(error_message) from exception

  def key_exists(self, redis_key) -> bool:
    """Checks if the key is saved in Redis.

    Args:
      key (str): The key to be checked.

    Returns:
      exists (bool): Boolean indicating if evidence is saved. 

    Raises:
      TurbiniaException: If Redis fails in checking the existence of the key.
    """
    try:
      return self.client.exists(redis_key)
    except redis.RedisError as exception:
      error_message = f'Error checking existence of {redis_key} in Redis'
      log.error(f'{error_message}: {exception}')
      raise TurbiniaException(error_message) from exception

  def write_hash_object(self, redis_key, object_dict):
    """Writes new hash object into redis. To save storage, the function does not
    write values that are null, empty lists or empty dictionaries. Thus, if the 
    value is deserialized from Redis into the original object, the default 
    values will be used for those attributes.

    Args:
      object_dict (dict[str]): A dictionary containing the serialized
      attributes that will be saved.

    Returns:
      redis_key (str): The key corresponding to the object in Redis
    """
    log.info(f'Writing hash object {redis_key} into Redis')
    for attribute_name, attribute_value in object_dict.items():
      if attribute_value not in EMPTY_JSON_VALUES:
        self.set_attribute(redis_key, attribute_name, attribute_value)

  def write_evidence(self, evidence_dict: dict[str], update=False) -> str:
    """Writes evidence into redis.

    Args:
      evidence_dict (dict[str]): A dictionary containing the serialized
        evidence attributes that will be saved.
      update (bool): Allows overwriting previous key and blocks writing new 
        ones.

    Returns:
      evidence_key (str): The key corresponding to the evidence in Redis
    
    Raises:
      TurbiniaException: If the attribute deserialization fails.
    """
    try:
      evidence_key = ':'.join(
          ('TurbiniaEvidence', json.loads(evidence_dict['id'])))
      evidence_hash = json.loads(evidence_dict.get('hash'))
    except (TypeError, ValueError) as exception:
      error_message = 'Error deserializing evidence attribute.'
      log.error(f'{error_message}: {exception}')
      raise TurbiniaException(error_message) from exception
    # Either updates or write new key
    if update == self.key_exists(evidence_key):
      self.write_hash_object(evidence_key, evidence_dict)
      if evidence_hash:
        self.set_attribute(
            'TurbiniaEvidenceHashes', evidence_hash, evidence_key)
      return evidence_key

  def get_evidence_data(self, evidence_id: str) -> dict:
    """Returns a dictionary representing an Evidence object given its ID.

    Args:
      evidence_id (str): The ID of the stored evidence.

    Returns:
      evidence_dict (dict): Dict containing evidence attributes. 
    """
    evidence_key = ':'.join(('TurbiniaEvidence', evidence_id))
    evidence_dict = {}
    for attribute_name, attribute_value in self.iterate_attributes(
        evidence_key):
      evidence_dict[attribute_name] = attribute_value
    return evidence_dict

  def get_evidence_summary(
      self, group: str = None, output: str = 'keys') -> dict | list | int:
    """Gets a summary of all evidences.

    Args:
      group (str): Name of the evidence attribute by which evidence will be
        grouped.
      output (str): Output of the function (keys | content | count).

    Returns:
      summary (dict | list | int): Object containing evidences. 
    """
    if output == 'count' and not group:
      return sum(1 for _ in self.iterate_keys('Evidence'))
    summary = {} if group else []
    for evidence_key in self.iterate_keys('Evidence'):
      evidence_dictionary = self.get_evidence_data(evidence_key.split(':')[1])
      stored_value = evidence_dictionary if output == 'content' else (
          evidence_key)
      if group:
        attribute_value = evidence_dictionary.get(group, None)
        if attribute_value not in summary:
          summary[attribute_value] = [stored_value] if output != 'count' else 1
        elif output == 'count':
          summary[attribute_value] += 1
        else:
          summary[attribute_value].append(stored_value)
        continue
      summary.append(stored_value)
    return summary

  def query_evidence(
      self, attribute_name: str, attribute_value: Any,
      output: str = 'keys') -> list | int:
    """Queries for evidences with the specified attribute attribute_value.

    Args:
      attribute_name (str): Name of the attribute to be queried.
      attribute_value (Any): Value stored in the attribute.
      output (str): Output of the function (keys | content | count).

    Returns:
      query_result (list | int): Result of the query. 
    """
    keys = []
    for evidence_key in self.iterate_keys('Evidence'):
      if stored_value := self.get_attribute(evidence_key, attribute_name):
        if (attribute_name == 'tasks' and attribute_value
            in stored_value) or stored_value == attribute_value or str(
                stored_value) == str(attribute_value):
          keys.append(evidence_key)
    if output == 'content':
      return [self.get_evidence_data(key.split(':')[1]) for key in keys]
    elif output == 'count':
      return len(keys)
    return keys

  def get_evidence_key_by_hash(self, file_hash: str) -> str | None:
    """Gets the evidence key given its hash.

    Args:
      file_hash (str): The hash of the stored evidence.

    Returns:
      key (str | None): Key of the stored evidence. 
    """
    try:
      if file_hash:
        return self.get_attribute(
            'TurbiniaEvidenceHashes', file_hash, decode_json=False)
    except TurbiniaException:
      return None

  def get_evidence_by_hash(self, file_hash: str) -> dict:
    """Gets the evidence given its hash.

    Args:
      file_hash (str): The hash of the stored evidence.

    Returns:
      evidence_dict (dict): Dict containing evidence attributes. 
    """
    evidence_id = self.get_evidence_key_by_hash(file_hash).split(':')[1]
    return self.get_evidence_data(evidence_id)
