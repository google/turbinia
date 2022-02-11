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
"""Handles management of the resource state file."""

from __future__ import unicode_literals

import logging
import os
import json

from turbinia import config
from turbinia import TurbiniaException

config.LoadConfig()
log = logging.getLogger('turbinia')


def RetrieveResourceState():
  """Creates a resource file if it doesn't exist and load resource state into a json object.
  
    Returns:
      json_load(dict): The resource state json object.
  """
  # Check if file exists and if not create it
  if not os.path.exists(config.RESOURCE_FILE):
    log.info(
        'Resource state file does not exist. '
        'Writing new one to {0:s}'.format(config.RESOURCE_FILE))
    with open(config.RESOURCE_FILE, 'w') as fh:
      fh.write("{}")
    fh.close()

  # Load file as json object
  try:
    with open(config.RESOURCE_FILE) as fh:
      json_load = json.load(fh)
  except ValueError as e:
    message = 'Can not load json from resource state file.'
    log.error(message)
    raise TurbiniaException(message)
  finally:
    fh.close()

  return json_load


def PreprocessResourceState(resource_id, task_id):
  """Adds the Evidence resource_id and/or task_id into the state file
       for tracking.

    Args:
      resource_id (str): The unique id representing the resource being tracked.
      task_id (str): The id of a given Task.
  """
  # Retrieve the resource state
  json_load = RetrieveResourceState()

  # Append task_id to existing resource else add new resource id.
  if resource_id in json_load.keys():
    if task_id not in json_load[resource_id]:
      log.debug(
          'Adding task {0:s} into the resource state file for resource {1:s}.'
          .format(task_id, resource_id))
      json_load[resource_id].append(task_id)
  else:
    log.debug(
        'Adding new resource {0:s} and associated task {1:s} to the resource state file.'
        .format(resource_id, task_id))
    json_load[resource_id] = [task_id]

  # Write back to state file.
  with open(config.RESOURCE_FILE, 'w') as fh:
    json.dump(json_load, fh)
    log.debug('The resource state file has been successfully updated.')
  fh.close()


def PostProcessResourceState(resource_id, task_id):
  """Removes the Evidence resource_id and/or task_id from the state file
       as it is no longer needed.
    
    Args:
      resource_id (str): The unique id representing the resource being tracked.
      task_id (str): The id of a given Task.
    
    Returns:
      is_detachable (bool): Whether the given resource can be postprocessed.
  """
  # Retrieve the resource state
  json_load = RetrieveResourceState()
  is_detachable = False

  # Either remove task id or remove resource id if it is last Task remaining.
  if resource_id in json_load.keys():
    tasks = json_load[resource_id]
    if task_id in tasks and len(tasks) == 1:
      log.debug(
          'Last task {0:s} remaining. Removing resource {1:s} from the resource state file.'
          .format(task_id, resource_id))
      json_load.pop(resource_id)
      is_detachable = True
    elif task_id in tasks:
      json_load[resource_id].remove(task_id)
      log.debug(
          'Removing task {0:s} with associated resource {1:s} from the resource state file.'
          .format(task_id, resource_id))

  # Write back to state file.
  with open(config.RESOURCE_FILE, 'w') as fh:
    json.dump(json_load, fh)
    log.debug('The resource state file has been successfully updated.')
  fh.close()

  return is_detachable
