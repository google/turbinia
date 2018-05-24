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

import logging

from google.cloud import datastore

from turbinia import config
from turbinia import TurbiniaException
from turbinia.workers import TurbiniaTask
from turbinia.workers import TurbiniaTaskResult

log = logging.getLogger('turbinia')

def get_state_manager():
  """Return state manager object based on config.

  Returns
    Initialized StateManager object.
  """
  config.LoadConfig()
  if config.STATE_MANAGER == 'Datastore':
    return DatastoreStateManager()
  elif config.STATE_MANAGER == 'None':
    return NullStateManager()
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
    """
    task_dict = {}
    for attr in task.STORED_ATTRIBUTES:
      if not hasattr(task, attr):
        raise TurbiniaException(
            'Task {0:s} does not have attribute {1:s}'.format(task.name, attr))
      task_dict[attr] = getattr(task, attr)
      if isinstance(task_dict[attr], str):
        task_dict[attr] = unicode(task_dict[attr])

    if task.result:
      for attr in task.result.STORED_ATTRIBUTES:
        if not hasattr(task.result, attr):
          raise TurbiniaException(
              'Task {0:s} result does not have attribute {1:s}'.format(
                  task.name, attr))
        task_dict[attr] = getattr(task.result, attr)
        if isinstance(task_dict[attr], str):
          task_dict[attr] = unicode(task_dict[attr])

    # Set all non-existent keys to None
    all_attrs = set(TurbiniaTask.STORED_ATTRIBUTES +
                    TurbiniaTaskResult.STORED_ATTRIBUTES)
    task_dict.update({k: None for k in all_attrs if not task_dict.has_key(k)})

    # Using the pubsub topic as an instance attribute in order to have a unique
    # namepace per Turbinia installation.
    # TODO(aarontp): Migrate this to actual Datastore namespaces
    config.LoadConfig()
    task_dict.update({'instance': config.PUBSUB_TOPIC})
    return task_dict

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
    self.client = datastore.Client()

  def update_task(self, task):
    with self.client.transaction():
      entity = self.client.get(task.state_key)
      if not entity:
        self.write_new_task(task)
        return
      entity.update(self.get_task_dict(task))
      log.debug('Updating task {0:s} in Datastore'.format(task.name))
      self.client.put(entity)


  def write_new_task(self, task):
    # Using the pubsub topic as part of the key in order to have unique entities
    # per Turbinia installation.
    key = self.client.key('TurbiniaTask', task.id)
    entity = datastore.Entity(key)
    entity.update(self.get_task_dict(task))
    log.info('Writing new task {0:s} into Datastore'.format(task.name))
    self.client.put(entity)
    task.state_key = key
    return key


class NullStateManager(BaseStateManager):
  """Does nothing, until an alternate datastore is added."""

  def __init__(self):
    self.client = None

  def update_task(self, task):
    log.debug(
        'Not updating task {0:s} (StateManager undefined)'.format(task.name))

  def write_new_task(self, task):
    log.info(
        'Not writing new task {0:s} (StateManager undefined)'.format(task.name))
    return 0
