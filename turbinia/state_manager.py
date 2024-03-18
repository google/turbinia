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
    #DELETE
    #if task_dict.get('run_time'):
    #  task_dict['run_time'] = task_dict['run_time'].total_seconds()

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

  def get_task_legacy(self, task_id: str) -> dict:
    """Returns a dictionary representing a Task object given its ID. This 
      function is used to get data of old TurbiniaTask objects stored as
      string in Redis.

    Args:
      task_id (str): The ID of the stored task.

    Returns:
      task_dict (dict): Dict containing task attributes. 
    """
    try:
      return json.loads(self.client.get(task_id))
    except redis.RedisError as exception:
      error_message = f'Error decoding key {task_id} in Redis'
      log.error(f'{error_message}: {exception}')
      raise TurbiniaException(error_message) from exception
  
  def get_task(self, task_id: str) -> dict:
    """Returns a dictionary representing a Task object given its ID.

    Args:
      task_id (str): The ID of the stored task.

    Returns:
      task_dict (dict): Dict containing task attributes. 
    """
    task_key = ':'.join(('TurbiniaTask', task_id))

    if self.get_key_type(task_key) == 'string':
      task_dict = self.get_task_legacy(task_id)
    else:
      task_dict = {}
      for attribute_name, attribute_value in self.iterate_attributes(
          task_key):
        task_dict[attribute_name] = attribute_value
    if task_dict.get('last_update'):
      task_dict['last_update'] = datetime.strptime(
          task_dict.get('last_update'), DATETIME_FORMAT)
    if task_dict.get('run_time'):
      task_dict['run_time'] = timedelta(seconds=task_dict['run_time'])

    return task_dict
  
  def validate_task(self, task, instance: str, days: int, group_id: str, user: str):
    if days:
      start_time = datetime.now() - timedelta(days=days)
      valid_days = task.get('last_update') > start_time
    else:
      valid_days = True
    valid_instance = not instance or task.get('instance') == instance
    valid_group = not group_id or task.get('group_id') == group_id
    valid_user = not user or task.get('requester') == user
    return valid_days and valid_instance and valid_group and valid_user

  def get_task_data(
      self, instance: str, days: int=0, task_id: str=None,
      request_id: str=None, group_id: str=None, user: str=None):
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
    # If task_id is passed, simply gets and validates the corresponding task
    if task_id:
      task = self.get_task(task_id)
      valid_request = not request_id or task.get('request_id') == request_id
      valid_task = self.validate_task(task, instance, days, group_id, user)
      return [task] if valid_request and valid_task else []

    request_key = f'TurbiniaRequest:{request_id}' if request_id else None

    # If request_id is passed, gets valid tasks from that request
    if request_key and self.key_exists(request_key):
      task_ids = self.get_attribute(
        request_key, 'task_ids', decode_json = True)
    # If no task_id or request_id is passed, gets all valid saved tasks
    else:
      task_ids = [task_key.split(':')[1] for task_key in self.iterate_keys('Task')]

    tasks = []

    for task_id in task_ids:
      task = self.get_task(task_id)
      if self.validate_task(task, instance, days, group_id, user):
        tasks.append(task)
    
    return tasks

  def format_task(self, task):
    task_dict = self.get_task_dict(task)
    task_dict['last_update'] = task_dict['last_update'].strftime(
        DATETIME_FORMAT)
    task_dict['start_time'] = task_dict['start_time'].strftime(DATETIME_FORMAT)
    if not task_dict.get('status'):
      task_dict['status'] = (
        f'Task scheduled at {datetime.now().strftime(DATETIME_FORMAT)}')
    if task_dict['run_time']:
      task_dict['run_time'] = task_dict['run_time'].total_seconds()
    for key, value in task_dict.items():
      try:
        task_dict[key] = json.dumps(value)
      except (TypeError, ValueError) as exception:
        error_message = f'Error serializing task attribute for task {task.id}.'
        log.error(f'{error_message}: {exception}')
        raise TurbiniaException(error_message) from exception
    return task_dict

  def update_request_task(self, task):
    request_key = ':'.join(('TurbiniaRequest', task.request_id))
    self.add_to_list(request_key, 'task_ids', task.id)
    request_last_update = datetime.strptime(self.get_attribute(
      request_key, 'last_update'), DATETIME_FORMAT)
    try:
      last_update = json.dumps(max(request_last_update, task.last_update).strftime(
        DATETIME_FORMAT))
    except redis.RedisError as exception:
      error_message = f'Error encoding key {request_key} in Redis'
      log.error(f'{error_message}: {exception}')
      raise TurbiniaException(error_message) from exception   
    self.set_attribute(request_key, 'last_update',last_update)
    statuses_to_remove = ['succesful_tasks', 'failed_tasks','running_tasks', 'queued_tasks']
    # 'successful' could be None or False, which means different things.
    # If False, the task has failed, If None, could be queued or running.
    if hasattr(task, 'succesful'):
      if task.successful:
        self.add_to_list(request_key, 'succesful_tasks', task.id)
        statuses_to_remove.remove('succesful_tasks')
      if task.successful is False:
        self.add_to_list(request_key, 'failed_tasks', task.id)
        statuses_to_remove.remove('failed_tasks')
      elif task.successful is None:
        if task.status:
          if 'running' in task.status:
            self.add_to_list(request_key, 'running_tasks', task.id)
            statuses_to_remove.remove('running_tasks')
        else:
          # 'successful' is None and 'status' is None
          self.add_to_list(request_key, 'queued_tasks', task.id)
          statuses_to_remove.remove('queued_tasks')
    for status_name in statuses_to_remove:
      self.remove_from_list(request_key, status_name, task.id)

  def write_new_task(self, task):
    """Writes task into redis.

    Args:
      task_dict (dict[str]): A dictionary containing the serialized
        request attributes that will be saved.
      update (bool): Allows overwriting previous key and blocks writing new 
        ones.

    Returns:
      request_key (str): The key corresponding to the evidence in Redis
    
    Raises:
      TurbiniaException: If the attribute deserialization fails.
    """
    log.info(f'Writing new task {task.name:s} into Redis')
    task_key = ':'.join(('TurbiniaTask', task.id))
    self.update_request_task(task)
    task_dict = self.format_task(task)
    self.write_hash_object(task_key, task_dict)
    task.state_key = task_key
    return task_key

  def update_task(self, task):
    task.touch()
    task_key = task.state_key
    if not task_key:
      self.write_new_task(task)
      return
    self.update_request_task(task)
    stored_task_dict = self.get_task(task_key)
    stored_evidence_size = stored_task_dict.get('evidence_size')
    stored_evidence_id = stored_task_dict.get('evidence_id')
    if not task.evidence_size and stored_evidence_size:
      task.evidence_size = stored_evidence_size
    if not task.evidence_id and stored_evidence_id:
      task.evidence_id = stored_evidence_id
    log.info(f'Updating task {task.name:s} in Redis')
    task_dict = self.format_task(task)
    self.write_hash_object(task_key, task_dict)
    return task_key

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
      self.client.hset(redis_key, attribute_name, json_value)
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
    for attribute in attributes:
      try:
        yield (attribute[0].decode(), json.loads(attribute[1]))
      except (TypeError, ValueError) as exception:
        error_message = f'Error decoding {attribute} in {key} in Redis'
        log.error(f'{error_message}: {exception}')
        raise TurbiniaException(error_message) from exception

  def key_exists(self, redis_key) -> bool:
    """Checks if the key is saved in Redis.

    Args:
      redis_key (str): The key to be checked.

    Returns:
      exists (bool): Boolean indicating if key is saved. 

    Raises:
      TurbiniaException: If Redis fails in checking the existence of the key.
    """
    try:
      return self.client.exists(redis_key)
    except redis.RedisError as exception:
      error_message = f'Error checking existence of {redis_key} in Redis'
      log.error(f'{error_message}: {exception}')
      raise TurbiniaException(error_message) from exception
    
  def attribute_exists(self, redis_key, attribute_name) -> bool:
    """Checks if the attribute of the hashed key is saved in Redis.

    Args:
      redis_key (str): The key to be checked.
      attribute_name (str): The attribute to be checked.

    Returns:
      exists (bool): Boolean indicating if attribute is saved. 

    Raises:
      TurbiniaException: If Redis fails in checking the existence.
    """
    try:
      return self.client.hexists(redis_key, attribute_name)
    except redis.RedisError as exception:
      error_message = (
        f'Error checking existence of attribute {attribute_name}'
        f'in {redis_key} in Redis')
      log.error(f'{error_message}: {exception}')
      raise TurbiniaException(error_message) from exception

  def get_key_type(self, redis_key) -> bool:
    """Gets the type of the Redis key.

    Args:
      redis_key (str): The key to be checked.

    Returns:
      type (str): Type of the Redis key. 

    Raises:
      TurbiniaException: If Redis fails in getting the type of the key.
    """
    try:
      return self.client.type(redis_key)
    except redis.RedisError as exception:
      error_message = f'Error getting type of {redis_key} in Redis'
      log.error(f'{error_message}: {exception}')
      raise TurbiniaException(error_message) from exception

  def add_to_list(self, redis_key, list_name, new_item, allow_repeated=False):
    """Appends new item to a list attribute in a hashed Redis object.

    Args:
      redis_key (str): Key of the Redis object.
      list_name (str): Name of the list attribute.
      new_item (Any): Item to be saved.
      repeated (bool): Allows repeated items to be saved.
    """
    if not self.attribute_exists(redis_key, list_name):
      list_attribute = [new_item]
    else:
      list_attribute = self.get_attribute(redis_key, list_name)
      if new_item not in list_attribute and not allow_repeated:
        list_attribute.append(new_item)
      try:
        self.set_attribute(redis_key, list_name, json.dumps(list_attribute))
      except (TypeError, ValueError) as exception:
        error_message = (
            f'Error encoding list {list_attribute} from {redis_key} in Redis')
        log.error(f'{error_message}: {exception}')
        raise TurbiniaException(error_message) from exception

  def remove_from_list(self, redis_key, list_name, item):
    """Removes an item from a list attribute in a hashed Redis object.

    Args:
      redis_key (str): Key of the Redis object.
      list_name (str): Name of the list attribute.
      item (Any): Item to be removed.
    """
    if not self.attribute_exists(redis_key, list_name):
      return
    list_attribute = self.get_attribute(redis_key, list_name)
    if item in list_attribute:
      list_attribute.remove(item)
    try:
      self.set_attribute(redis_key, list_name, json.dumps(list_attribute))
    except (TypeError, ValueError) as exception:
      error_message = (
          f'Error encoding list {list_attribute} from {redis_key} in Redis')
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
      evidence_id = json.loads(evidence_dict['id'])
      evidence_hash = json.loads(evidence_dict.get('hash'))
      request_key = ':'.join(
          ('TurbiniaRequest', json.loads(evidence_dict['request_id'])))
    except (TypeError, ValueError) as exception:
      error_message = 'Error deserializing evidence attribute.'
      log.error(f'{error_message}: {exception}')
      raise TurbiniaException(error_message) from exception
    evidence_key = ':'.join(('TurbiniaEvidence', evidence_id))
    # Either updates or writes new key
    if update == self.key_exists(evidence_key):
      self.write_hash_object(evidence_key, evidence_dict)
      if evidence_hash:
        self.set_attribute(
            'TurbiniaEvidenceHashes', evidence_hash, evidence_key)
      if not update:
        self.add_to_list(request_key, 'evidence_ids', evidence_id)
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

  def write_request(self, request_dict: dict, update=False):
    """Writes request into redis.

    Args:
      request_dict (dict[str]): A dictionary containing the serialized
        request attributes that will be saved.
      update (bool): Allows overwriting previous key and blocks writing new 
        ones.

    Returns:
      request_key (str): The key corresponding to the evidence in Redis
    
    Raises:
      TurbiniaException: If the attribute deserialization fails.
    """
    try:
      request_key = ':'.join(
          ('TurbiniaRequest', json.loads(request_dict['request_id'])))
    except (TypeError, ValueError) as exception:
      error_message = 'Error deserializing request attribute.'
      log.error(f'{error_message}: {exception}')
      raise TurbiniaException(error_message) from exception
    try:
      if not request_dict.get('last_update'):
        request_dict['start_time'] = json.dumps(datetime.now().strftime(DATETIME_FORMAT))
      if not request_dict.get('last_update'):
        request_dict['last_update'] = json.dumps(datetime.now().strftime(DATETIME_FORMAT))
      request_dict['status'] = json.dumps(f'Task scheduled at {datetime.now().strftime(DATETIME_FORMAT)}')
    except redis.RedisError as exception:
      error_message = f'Error encoding key {request_key} in Redis'
      log.error(f'{error_message}: {exception}')
      raise TurbiniaException(error_message) from exception
    # Either updates or write new key
    if update == self.key_exists(request_key):
      self.write_hash_object(request_key, request_dict)
      return request_key

  def get_request_data(self, request_id: str) -> dict:
    """Returns a dictionary representing a Request object given its ID.

    Args:
      request_id (str): The ID of the stored request.

    Returns:
      request_dict (dict): Dict containing request attributes. 
    """
    request_key = ':'.join(('TurbiniaRequest', request_id))
    request_dict = {}
    for attribute_name, attribute_value in self.iterate_attributes(request_key):
      request_dict[attribute_name] = attribute_value
    request_dict['last_update'] = datetime.strptime(
          request_dict.get('last_update'), DATETIME_FORMAT)
    request_dict['start_time'] = datetime.strptime(
          request_dict.get('start_time'), DATETIME_FORMAT)
    return request_dict

  def query_requests(
      self, attribute_name: str, attribute_value: Any,
      output: str = 'keys') -> list | int:
    """Queries for requests with the specified attribute attribute_value.

    Args:
      attribute_name (str): Name of the attribute to be queried.
      attribute_value (Any): Value stored in the attribute.
      output (str): Output of the function (keys | content | count).

    Returns:
      query_result (list | int): Result of the query. 
    """
    keys = []
    for request_key in self.iterate_keys('request'):
      if stored_value := self.get_attribute(request_key, attribute_name):
        if (attribute_name == 'evidence_ids' and attribute_value in stored_value
           ) or (attribute_name == 'task_ids' and attribute_value
                 in stored_value) or stored_value == attribute_value or str(
                     stored_value) == str(attribute_value):
          keys.append(request_key)
    if output == 'content':
      return [self.get_request_data(key.split(':')[1]) for key in keys]
    elif output == 'count':
      return len(keys)
    return keys
