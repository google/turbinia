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


def ValidateStateFile():
  """Checks if resource file exists and the json object can be properly loaded."""
  # Check if file exists and if not create it
  if not os.path.exists(config.RESOURCE_FILE):
    log.info(
        'Resource state file does not exist. '
        'Writing new one to {0:s}'.format(config.RESOURCE_FILE))
    with open(config.RESOURCE_FILE, 'w') as fh:
      fh.write("{}")
    fh.close()

  # Ensure file can be loaded as json object
  try:
    with open(config.RESOURCE_FILE) as fh:
      json_load = json.load(fh)
    fh.close()
  except ValueError as e:
    raise TurbiniaException('Can not load json from file.')


def PreprocessResourceState(resource_id, task_id):
  """Adds the Evidence resource_id and/or task_id into the state file
       for tracking.

    Args:
      resource_id (str): The unique id representing the resource being tracked.
      task_id (str): The id of a given Task.
    """
  ValidateStateFile()
  json_load = json.load(open(config.RESOURCE_FILE))

  # Append task_id to existing resource else add new resource id.
  if resource_id in json_load.keys():
    if task_id not in json_load[resource_id]:
      json_load[resource_id].append(task_id)
  else:
    json_load[resource_id] = [task_id]

  # Write back to state file.
  with open(config.RESOURCE_FILE, 'w') as fh:
    json.dump(json_load, fh)
  fh.close()


def PostProcessResourceState(resource_id, task_id):
  """Removes the Evidence resource_id and/or task_id from the state file
       as it is no longer needed.
    
    Args:
      resource_id (str): The unique id representing the resource being tracked.
      task_id (str): The id of a given Task.
    """
  ValidateStateFile()
  json_load = json.load(open(config.RESOURCE_FILE))
  isDetachable = False

  # Either remove task id or remove resource id if it is last Task remaining.
  if resource_id in json_load.keys():
    vals = json_load[resource_id]
    if task_id in vals and len(vals) == 1:
      json_load.pop(resource_id)
      isDetachable = True
    elif task_id in vals:
      json_load[resource_id].remove(task_id)

  # Write back to state file.
  with open(config.RESOURCE_FILE, 'w') as fh:
    json.dump(json_load, fh)
  fh.close()

  return isDetachable
