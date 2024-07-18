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

import codecs
import json
import logging
import sys
from datetime import datetime
from datetime import timedelta
from typing import Any, List, Dict, Optional

import six

from turbinia import config
from turbinia.config import DATETIME_FORMAT
from turbinia import TurbiniaException
from turbinia.redis_client import RedisClient, RedisClientError

config.LoadConfig()
if 'unittest' in sys.modules.keys():
  from google.auth import exceptions as auth_exceptions
  import redis

if config.STATE_MANAGER.lower() == 'redis':
  import redis
else:
  msg = f'State Manager type "{config.STATE_MANAGER:s}" not implemented'
  raise TurbiniaException(msg)

MAX_DATASTORE_STRLEN = 1500
log = logging.getLogger(__name__)


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
    error = f'State Manager type "{config.STATE_MANAGER:s}" not implemented'
    raise TurbiniaException(error)


class BaseStateManager:
  """Class to manage Turbinia state persistence."""

  def get_task_dict(self, task) -> Dict[str, Any]:
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
    self.redis_client = RedisClient()

  def set_client(self, redis_client):
    self.redis_client = redis_client

  def _validate_data(self, data):
    return data

  def get_task(self, task_id: str) -> dict:
    """Returns a dictionary representing a Task object given its ID.

    Args:
      task_id (str): The ID of the stored task.

    Returns:
      task_dict (dict): Dict containing task attributes. 
    """
    task_key = ':'.join(('TurbiniaTask', task_id))
    task_dict = {}
    try:
      for attribute_name, attribute_value in self.redis_client.iterate_attributes(
          task_key):
        task_dict[attribute_name] = attribute_value
      if task_dict.get('last_update'):
        task_dict['last_update'] = datetime.strptime(
            task_dict.get('last_update'), DATETIME_FORMAT)
      if task_dict.get('run_time'):
        task_dict['run_time'] = timedelta(seconds=task_dict['run_time'])
    except RedisClientError as exception:
      log.error(f'Error retrieving task data {exception}')
    return task_dict

  def validate_task(
      self, task, instance: str, days: int, group_id: str, user: str) -> bool:
    """Returns True if the Task matches the required filters."""
    result: bool = False
    try:
      if days:
        start_time = datetime.now() - timedelta(days=days)
        valid_days = task.get('last_update') > start_time
      else:
        valid_days = True
      valid_instance = not instance or task.get('instance') == instance
      valid_group = not group_id or task.get('group_id') == group_id
      valid_user = not user or task.get('requester') == user
      result = valid_days and valid_instance and valid_group and valid_user
    except TypeError as exception:
      log.error(f'Error validating task {task.get("id")}: {exception}')
    return result

  def get_task_data(
      self, instance: str, days: int = 0, task_id: str = None,
      request_id: str = None, group_id: str = None,
      user: str = None) -> List[Dict]:
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
    if task_id and request_id:
      raise TurbiniaException(
          'You can provide a task_id or request_id but not both.')

    task_ids = []

    # If task_id is passed, simply gets and validates the corresponding task
    if task_id:
      task = self.get_task(task_id)
      valid_request = not request_id or task.get('request_id') == request_id
      valid_task = self.validate_task(task, instance, days, group_id, user)
      return [task] if valid_request and valid_task else []

    # If request_id is passed, gets valid tasks from that request
    elif request_id:
      request_key = self.redis_client.build_key_name('request', request_id)
      if request_key and self.redis_client.key_exists(request_key):
        task_ids = self.redis_client.get_attribute(
            request_key, 'task_ids', decode_json=True)

    # If no task_id or request_id is passed, gets all valid saved tasks
    else:
      task_ids = [
          task_key.split(':')[1]
          for task_key in self.redis_client.iterate_keys('Task')
      ]

    tasks = []

    for task_id in task_ids:
      task = self.get_task(task_id)
      if self.validate_task(task, instance, days, group_id, user):
        tasks.append(task)

    return tasks

  def update_request_task(self, task) -> None:
    """Adds a Turbinia task to the corresponding request list.
    
    Args:
      task (TurbiniaTask): Turbinia task object.
    """
    request_key = self.redis_client.build_key_name('request', task.request_id)
    task_key = self.redis_client.build_key_name('task', task.id)
    try:
      self.redis_client.add_to_list(request_key, 'task_ids', task.id)
      request_last_update = datetime.strptime(
          self.redis_client.get_attribute(request_key, 'last_update'),
          DATETIME_FORMAT)
      last_update = json.dumps(
          max(request_last_update, task.last_update).strftime(DATETIME_FORMAT))
      self.redis_client.set_attribute(request_key, 'last_update', last_update)
      statuses_to_remove = [
          'successful_tasks', 'failed_tasks', 'running_tasks', 'queued_tasks'
      ]
      # 'successful' could be None or False, which means different things.
      # If False, the task has failed, If None, could be queued or running.
      if hasattr(task.result, 'successful'):
        if task.result.successful:
          self.redis_client.add_to_list(
              request_key, 'successful_tasks', task.id)
          statuses_to_remove.remove('successful_tasks')
        elif task.result.successful is False:
          self.redis_client.add_to_list(request_key, 'failed_tasks', task.id)
          statuses_to_remove.remove('failed_tasks')
      task_status = self.redis_client.get_attribute(task_key, 'status')
      if task_status == 'running':
        self.redis_client.add_to_list(request_key, 'running_tasks', task.id)
        statuses_to_remove.remove('running_tasks')
      elif task_status is None or task_status == 'queued':
        self.redis_client.add_to_list(request_key, 'queued_tasks', task.id)
        statuses_to_remove.remove('queued_tasks')
      for status_name in statuses_to_remove:
        self.redis_client.remove_from_list(request_key, status_name, task.id)
    except RedisClientError as exception:
      error_message = f'Error encoding key {request_key} in Redis'
      log.error(f'{error_message}: {exception}')

  def write_new_task(self, task) -> Optional[str]:
    """Writes task into redis.

    Args:
      task_dict (dict[str]): A dictionary containing the serialized
        request attributes that will be saved.

    Returns:
      task_key Optional[str]: The key corresponding for the task.
    """
    log.info(f'Writing metadata for new task {task.name:s} with id {task.id:s}')
    try:
      task_key = self.redis_client.build_key_name('task', task.id)
    except ValueError as exception:
      log.error(exception)
    try:
      task_dict = self.update_task_helper(task)
      if task_key := self.redis_client.write_hash_object(task_key, task_dict):
        task.state_key = task_key
        self.update_request_task(task)
      return task_key
    except RedisClientError as exception:
      log.error(f'Error writing task {task.id} data: {exception}')
    except TurbiniaException as exception:
      log.error(f'Error decoding task {task.id} metadata: {exception}')

  def update_task_helper(self, task) -> Dict[str, Any]:
    """Retrieves TurbiniaTask metadata to update time-related and status
    attributes.

    Args:
      task (TurbiniaTask): A TurbiniaTask object.

    Returns:
      task_dict: A dictionary containing updated task metadata.
    """
    task_dict = self.get_task_dict(task)
    task_dict['last_update'] = task_dict['last_update'].strftime(
        DATETIME_FORMAT)
    task_dict['start_time'] = task_dict['start_time'].strftime(DATETIME_FORMAT)
    if task_dict['run_time']:
      task_dict['run_time'] = task_dict['run_time'].total_seconds()
    for key, value in task_dict.items():
      try:
        task_dict[key] = json.dumps(value)
      except (TypeError, ValueError) as exception:
        error_message = (
            f'Error serializing attribute {key}:{value} for task {task.id}.')
        log.error(f'{error_message}: {exception}')
        raise TurbiniaException(error_message) from exception
    return task_dict

  def update_task(self, task) -> Optional[str]:
    """Updates a Turbinia task key.
    
    Args:
      task: A TurbiniaTask object.

    Returns:
      task_key: The task key associated with this TurbiniaTask
        or None.
    """
    task.touch()
    task_key = task.state_key
    if not task_key:
      # if the task does not have a state_key we will write a new object.
      if task_key := self.write_new_task(task):
        return task_key
      return None
    try:
      log.debug(f'Updating metadata for task {task.name} with key {task.id}')
      task_dict = self.update_task_helper(task)
      self.redis_client.write_hash_object(task_key, task_dict)
      # Add the task to the associated TurbiniaReqest task_ids list.
      self.update_request_task(task)
      # Set the current status for the TurbiniaRequest
      request_status = self.get_request_status(task.request_id)
      request_key = self.redis_client.build_key_name('request', task.request_id)
      self.redis_client.set_attribute(
          request_key, 'status', json.dumps(request_status))
    except TurbiniaException as exception:
      log.error(f'Error uupdating task {task.id}: {exception}')
    except RedisClientError as exception:
      log.error(f'Error writing task data for task {task.id}: {exception}')
    return task_key

  def write_evidence(self, evidence_dict: dict[str]) -> str:
    """Writes evidence into redis.

    Args:
      evidence_dict (dict[str]): A dictionary containing the serialized
        evidence attributes that will be saved.

    Returns:
      evidence_key (str): The key corresponding to the evidence in Redis
    
    Raises:
      TurbiniaException: If the attribute deserialization fails.
    """
    evidence_key = ''
    request_key = ''
    try:
      evidence_id = json.loads(evidence_dict['id'])
      evidence_hash = json.loads(evidence_dict.get('hash'))
      request_id = json.loads(evidence_dict['request_id'])
      request_key = self.redis_client.build_key_name('request', request_id)
      evidence_key = self.redis_client.build_key_name('evidence', evidence_id)
    except (TypeError, ValueError) as exception:
      error_message = 'Error deserializing evidence attribute.'
      log.error(f'{error_message}: {exception}')
      raise TurbiniaException(error_message) from exception

    # Don't keep the config value since we don't really use it
    # and it can be quite verbose if a complex recipe is used.
    try:
      evidence_dict.pop('config')
    except KeyError:
      # Nothing to do if the key doesn't exist.
      pass

    try:
      if not self.redis_client.key_exists(evidence_key):
        self.redis_client.write_hash_object(evidence_key, evidence_dict)
        if evidence_hash:
          self.redis_client.set_attribute(
              'TurbiniaEvidenceHashes', evidence_hash, evidence_key)
      self.redis_client.add_to_list(request_key, 'evidence_ids', evidence_id)
      return evidence_key
    except RedisClientError as exception:
      log.error(f'There was an error writing data to Redis: {exception}')

  def get_evidence_data(self, evidence_id: str) -> dict:
    """Returns a dictionary representing an Evidence object given its ID.

    Args:
      evidence_id (str): The ID of the stored evidence.

    Returns:
      evidence_dict (dict): Dict containing evidence attributes. 
    """
    evidence_key = ':'.join(('TurbiniaEvidence', evidence_id))
    evidence_dict = {}
    for attribute_name, attribute_value in self.redis_client.iterate_attributes(
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
      return sum(1 for _ in self.redis_client.iterate_keys('Evidence'))
    summary = {} if group else []
    for evidence_key in self.redis_client.iterate_keys('Evidence'):
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
    for evidence_key in self.redis_client.iterate_keys('Evidence'):
      if stored_value := self.redis_client.get_attribute(evidence_key,
                                                         attribute_name):
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
        return self.redis_client.get_attribute(
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

  def write_request(self, request_dict: dict, overwrite=False):
    """Writes request into redis.

    Args:
      request_dict (dict[str]): A dictionary containing the serialized
        request attributes that will be saved.
      overwrite (bool): Allows overwriting previous key and blocks writing new 
        ones.

    Returns:
      request_key (str): The key corresponding to the evidence in Redis
    
    Raises:
      TurbiniaException: If the attribute deserialization fails or tried to
          overwrite an existing key without overwrite=True
    """
    try:
      request_id = json.loads(request_dict['request_id'])
      request_key = self.redis_client.build_key_name('request', request_id)
    except (TypeError, ValueError) as exception:
      error_message = 'Error deserializing request attribute.'
      log.error(f'{error_message}: {exception}')
      raise TurbiniaException(error_message) from exception
    try:
      if not request_dict.get('start_time'):
        request_dict['start_time'] = json.dumps(
            datetime.now().strftime(DATETIME_FORMAT))
      if not request_dict.get('last_update'):
        request_dict['last_update'] = json.dumps(
            datetime.now().strftime(DATETIME_FORMAT))
      # Either updates or write new key
      if not overwrite and self.redis_client.key_exists(request_key):
        raise TurbiniaException(
            f'Error, attempted to overwrite an existing key: {request_key} '
            f'but overwrite was not set.')
      else:
        self.redis_client.write_hash_object(request_key, request_dict)
    except redis.RedisError as exception:
      error_message = f'Error encoding key {request_key} in Redis'
      log.error(f'{error_message}: {exception}')
      raise TurbiniaException(error_message) from exception

    return request_key

  def get_request_data(self, request_id: str) -> dict:
    """Returns a dictionary representing a Request object given its ID.

    Args:
      request_id (str): The ID of the stored request.

    Returns:
      request_dict (dict): Dict containing request attributes. 
    """
    request_key = self.redis_client.build_key_name('request', request_id)
    request_dict = {}
    try:
      for (
          attribute_name,
          attribute_value) in self.redis_client.iterate_attributes(request_key):
        request_dict[attribute_name] = attribute_value
      request_dict['last_update'] = datetime.strptime(
          request_dict.get('last_update'), DATETIME_FORMAT)
      request_dict['start_time'] = datetime.strptime(
          request_dict.get('start_time'), DATETIME_FORMAT)
    except TurbiniaException as exception:
      log.error(f'Error retrieving request data: {exception}')
    return request_dict

  def get_request_status(self, request_id):
    request_data = self.get_request_data(request_id)
    request_status = 'pending'
    finished_tasks = len(request_data['failed_tasks']) + (
        len(request_data['successful_tasks']))
    all_tasks_finished = finished_tasks == len(request_data['task_ids'])
    if len(request_data['task_ids']) == len(request_data['successful_tasks']):
      request_status = 'successful'
    elif len(request_data['task_ids']) == len(request_data['failed_tasks']):
      request_status = 'failed'
    elif len(request_data['running_tasks']) > 0:
      request_status = 'running'
    elif len(request_data['failed_tasks']) > 0 and all_tasks_finished:
      request_status = 'completed_with_errors'
    else:
      request_status = 'pending'
    log.info(f'Request {request_id} status: {request_status}')
    return request_status

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
    for request_key in self.redis_client.iterate_keys('request'):
      if stored_value := self.redis_client.get_attribute(request_key,
                                                         attribute_name):
        if (attribute_name in ('evidence_ids', 'task_ids') and attribute_value
            in stored_value) or stored_value == attribute_value or str(
                stored_value) == str(attribute_value):
          keys.append(request_key)
    if output == 'content':
      return [self.get_request_data(key.split(':')[1]) for key in keys]
    elif output == 'count':
      return len(keys)
    return keys
