# -*- coding: utf-8 -*-
# Copyright 2024 Google Inc.
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
"""State manager helper"""

import logging
import json
import redis

from typing import Any, Iterator, Dict

from turbinia import config

log = logging.getLogger(__name__)


class RedisClientError(Exception):
  """This class handles Redis client errors."""
  pass


class RedisClient:
  """This class handles Redis operations on keys/values."""

  def __init__(self, redis_client=None):
    self.client = redis_client
    if not self.client:
      self.client = redis.StrictRedis(
          host=config.REDIS_HOST, port=config.REDIS_PORT, db=config.REDIS_DB,
          socket_timeout=10, socket_keepalive=True, socket_connect_timeout=10)

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
      RedisClientError: if there was an error setting the attribute value.
    """
    try:
      values_set = self.client.hset(redis_key, attribute_name, json_value)
      return bool(values_set)
    except redis.RedisError as exception:
      error_message = f'Error setting {attribute_name} for key {redis_key}'
      log.error(f'{error_message}: {exception}')
      raise RedisClientError(error_message) from exception

  def iterate_keys(self, key_type: str) -> Iterator[str]:
    """Iterates over the Turbinia keys of a specific type.

    Args:
      key_type (str): The type of the Turbinia key (e.g. Task, Evidence)

    Yields:
      key (str): Decoded key of stored Turbinia object. 

    Raises:
      RedisClientError: If Redis fails in getting the keys or if
        decode fails.
    """
    valid_key_types = ('evidence', 'task', 'request')
    if key_type.lower() not in valid_key_types:
      raise RedisClientError(f'Invalid key type: {key_type}')

    try:
      keys = self.client.scan_iter(f'Turbinia{key_type.title()}:*', count=1000)
    except redis.RedisError as exception:
      error_message = f'Error getting {key_type} keys in Redis'
      log.error(f'{error_message}: {exception}')
      raise RedisClientError(error_message) from exception
    try:
      for data in keys:
        yield data.decode()
    except ValueError as exception:
      error_message = 'Error decoding key in Redis'
      log.error(f'{error_message}: {exception}')
      raise RedisClientError(error_message) from exception

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
      RedisClientError: If Redis fails in getting the attribute or if
        json loads fails.
    """
    try:
      attribute_value = self.client.hget(redis_key, attribute_name)
      if not attribute_value:
        message = f'Attribute {attribute_name} for key {redis_key} not found.'
        log.warning(message)
    except redis.RedisError as exception:
      error_message = (
          f'Error getting {attribute_name} from {redis_key} in Redis')
      log.error(f'{error_message}: {exception}')
      raise RedisClientError(error_message) from exception
    if decode_json and attribute_value:
      try:
        return json.loads(attribute_value)
      except (TypeError, ValueError) as exception:
        error_message = (
            f'Error decoding JSON {attribute_name} on {redis_key} '
            f'in Redis')
        log.error(f'{error_message}: {exception}')
        raise RedisClientError(error_message) from exception
    else:
      return attribute_value

  def iterate_attributes(self, key: str) -> Iterator[tuple]:
    """Iterates over the attribute names of the Redis hash object.

    Args:
      key (str): The key of the stored hash object.

    Yields:
      attribute_name (tuple): Decoded name of object attribute.

    Raises:
      RedisClientError: If Redis fails in getting the attributes or if
        decode or json loads fails. 
    """
    try:
      for attribute in self.client.hscan_iter(key, count=100):
        if attribute:
          try:
            attribute_name = attribute[0].decode()
            attribute_value = json.loads(attribute[1])
            yield (attribute_name, attribute_value)
          except (TypeError, ValueError) as exception:
            error_message = (
                f'Error decoding JSON value for {attribute_name} on {key} '
                f'in Redis')
            log.error(f'{error_message}: {exception}')
            raise RedisClientError(error_message) from exception
    except (redis.exceptions.ResponseError, redis.RedisError) as exception:
      error_message = f'Error getting attributes from {key}'
      log.error(f'{error_message}: {exception}')
      raise RedisClientError(error_message) from exception

  def build_key_name(self, key_type: str, identifier: str) -> str:
    """Returns a valid redis key name.

    Args:
      key_type (str):  The type of key (e.g. request, task, evidence).
      identifier (str): The ID used to build the key name.
    
    Returns:
      str: A valid Redis key name.

    Raises:
      ValueError: If an invalid key type was provided.
    """
    redis_key = ''
    if key_type == 'request':
      redis_key = f'TurbiniaRequest:{identifier}'
    elif key_type == 'task':
      redis_key = f'TurbiniaTask:{identifier}'
    elif key_type == 'evidence':
      redis_key = f'TurbiniaEvidence:{identifier}'
    else:
      raise ValueError('{key_type} is not a valid type of key.')
    return redis_key

  def key_exists(self, redis_key: str) -> bool:
    """Checks if the key is saved in Redis.

    Args:
      redis_key (str): The redis key name to be checked.

    Returns:
      exists (bool): Boolean indicating if key is saved. 

    Raises:
      RedisClientError: If Redis fails in checking the existence of the key.
    """
    try:
      return self.client.exists(redis_key)
    except redis.RedisError as exception:
      error_message = f'Error checking existence of {redis_key} in Redis'
      log.error(f'{error_message}: {exception}')
      raise RedisClientError(error_message) from exception

  def attribute_exists(self, redis_key: str, attribute_name: str) -> bool:
    """Checks if the attribute of the hashed key is saved in Redis.

    Args:
      redis_key (str): The key to be checked.
      attribute_name (str): The attribute to be checked.

    Returns:
      exists (bool): Boolean indicating if attribute is saved. 

    Raises:
      RedisClientError: If Redis fails in checking the existence.
    """
    try:
      return self.client.hexists(redis_key, attribute_name)
    except redis.RedisError as exception:
      error_message = (
          f'Error checking existence of attribute {attribute_name}'
          f' for key {redis_key}')
      log.error(f'{error_message}: {exception}')
      raise RedisClientError(error_message) from exception

  def get_key_type(self, redis_key: str) -> bool:
    """Gets the type of the Redis key.

    Args:
      redis_key (str): The key to be checked.

    Returns:
      type (str): Type of the Redis key. 

    Raises:
      RedisClientError: If Redis fails in getting the type of the key.
    """
    try:
      return self.client.type(redis_key)
    except redis.RedisError as exception:
      error_message = f'Error getting type for key {redis_key}'
      log.error(f'{error_message}: {exception}')
      raise RedisClientError(error_message) from exception

  def add_to_list(
      self, redis_key: str, list_name: str, new_item: Any,
      allow_repeated: bool = False) -> None:
    """Appends new item to a list attribute in a hashed Redis object.

    Args:
      redis_key: Key of the Redis object.
      list_name: Name of the list attribute.
      new_item: Item to be saved.
      repeated: Allows repeated items to be saved.

    Raises:
      RedisClientError: If there was an error writing to Redis.
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
      error_message = f'Error encoding list {list_attribute} from {redis_key}'
      log.error(f'{error_message}: {exception}')
      raise RedisClientError(error_message) from exception

  def remove_from_list(self, redis_key: str, list_name: str, item: Any) -> None:
    """Removes an item from a list attribute in a hashed Redis object.

    Args:
      redis_key: Key of the Redis object.
      list_name: Name of the list attribute.
      item: Item to be removed.

    Raises:
      RedisClientError: If there was an error writing to Redis.
    """
    if not self.attribute_exists(redis_key, list_name):
      return
    list_attribute = self.get_attribute(redis_key, list_name)
    if item in list_attribute:
      list_attribute.remove(item)
    try:
      self.set_attribute(redis_key, list_name, json.dumps(list_attribute))
    except (TypeError, ValueError) as exception:
      error_message = f'Error encoding list {list_attribute} from {redis_key}'
      log.error(f'{error_message}: {exception}')
      raise RedisClientError(error_message) from exception

  def write_hash_object(
      self, redis_key: str, object_dict: Dict[str, Any]) -> str:
    """Writes new hash object into redis. 

    Args:
      object_dict: A dictionary containing the serialized
        attributes that will be saved.

    Returns:
      redis_key: The key corresponding to the object in Redis
    
    Raises:
      RedisClientError: if there was an error writing the key.
    """
    log.debug(f'Updating key {redis_key}')
    try:
      self.client.hset(redis_key, mapping=object_dict)
    except redis.RedisError as exception:
      error_message = f'Error writing {redis_key}'
      log.error(f'{error_message}: {exception}')
      raise RedisClientError(error_message) from exception
    return redis_key
