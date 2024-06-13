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
"""Core classes for Turbinia Requests and Messaging components."""

import codecs
import copy
import json
import uuid
import logging
import six

from datetime import datetime

from turbinia import evidence as turbinia_evidence
from turbinia import TurbiniaException
from turbinia.config import DATETIME_FORMAT

log = logging.getLogger(__name__)


class TurbiniaRequest:
  """An object to request evidence to be processed.

  Attributes:
    evidence (list): A list of Evidence objects.
    failed_tasks (list): List of failed tasks.
    group_id(str): A client specified group id for this request.
    group_name (str): Name for grouping evidence.
    last_update (datetime.datetime): Last modification timestmap. 
    queued_tasks (list): List of queued tasks.
    reason (str): Reason or justification for Turbinia requests.
    recipe(dict): Recipe to use when processing this request.
    request_id(str): A client specified ID for this request.
    requester(str): The username of who made the request.
    running_tasks (list): List of running tasks.
    start_time (datetime.datetime): Task start timestamp.
    status (str): The status of the request.
    successful_tasks (list): List of successful tasks.
    task_ids (list): List of all tasks associated with the request.
    type (str): 'TurbiniaRequest' or class name.

  Note:
    Objects of this class will be stored by the state manager. The state
    manager will persist all attributes that are serializable to JSON by
    calling to_json(). Evidence objects are not serializable, but the
    evidence identifiers (IDs) are. Evidence IDs are stored in the
    evidence_ids key of the JSON object.
  """

  def __init__(
      self, request_id=None, group_id=None, requester=None, recipe=None,
      evidence=None, group_name=None, reason=None):
    """Initialization for TurbiniaRequest."""
    self.evidence = evidence if evidence else []
    if evidence and len(evidence) > 0:
      self.original_evidence = {'id': evidence[0].id, 'name': evidence[0].name}
    else:
      self.original_evidence = {}
    self.failed_tasks = []
    self.group_id = group_id if group_id else uuid.uuid4().hex
    self.group_name = group_name if group_name else ''
    self.last_update = datetime.now().strftime(DATETIME_FORMAT)
    self.queued_tasks = []
    self.reason = reason if reason else ''
    self.recipe = recipe if recipe else {'globals': {}}
    self.request_id = request_id if request_id else uuid.uuid4().hex
    self.requester = requester if requester else 'user_unspecified'
    self.running_tasks = []
    self.start_time = datetime.now().strftime(DATETIME_FORMAT)
    self.status = 'pending'
    self.successful_tasks = []
    self.task_ids = []
    self.type = self.__class__.__name__

  def to_json(self, json_values=False):
    """Convert object to JSON.

    Args:
      json_values (bool): Returns only values of the dictionary as json strings
        instead of the entire dictionary.

    Returns:
      A JSON serialized object.
    """
    serializable = copy.deepcopy(self.__dict__)
    if json_values:
      if evidence_list := serializable.pop('evidence'):
        if not serializable.get('original_evidence') and len(evidence_list) > 0:
          serializable['original_evidence'] = {
              'name': evidence_list[0].name,
              'id': evidence_list[0].id
          }
        serializable['evidence_ids'] = [
            evidence.id for evidence in evidence_list
        ]
      serialized = {}
      try:
        for attribute_name, attribute_value in serializable.items():
          serialized[attribute_name] = json.dumps(attribute_value)
      except TypeError as exception:
        msg = (
            f'JSON serialization of TurbiniaRequest object {self.type} '
            f'failed: {str(exception)}')
        raise TurbiniaException(msg) from exception
    else:
      serializable['evidence'] = [
          x.serialize() for x in serializable['evidence']
      ]
      try:
        serialized = json.dumps(serializable)
      except TypeError as exception:
        msg = (
            f'JSON serialization of TurbiniaRequest object {self.type} '
            f'failed: {str(exception)}')
        raise TurbiniaException(msg) from exception
    return serialized

  def from_json(self, json_str):
    """Loads JSON serialized data into self.

    Args:
      json_str (str): Json serialized TurbiniaRequest object.

    Raises:
      TurbiniaException: If json can not be loaded, or deserialized object is
          not of the correct type.
    """
    try:
      if isinstance(json_str, six.binary_type):
        json_str = codecs.decode(json_str, 'utf-8')
      obj = json.loads(json_str)
    except ValueError as exception:
      raise TurbiniaException(
          f'Can not load json from string {str(exception):s}') from exception

    if obj.get('type', None) != self.type:
      raise TurbiniaException(
          f'Deserialized object does not have type of {self.type:s}')

    obj['evidence'] = [
        turbinia_evidence.evidence_decode(e) for e in obj['evidence']
    ]
    # pylint: disable=attribute-defined-outside-init
    self.__dict__ = obj


class TurbiniaMessageBase:
  """Base class to define common functions and interfaces around client/server
    communication.
  """

  def check_messages(self):
    """Check queue for any messages.

    Returns:
      list[TurbiniaRequest]: all new evidence requests
    """

    raise NotImplementedError

  @staticmethod
  def _validate_message(message):
    """Validates incoming messages, returns them as a new TurbiniaRequest
    object.

    Args:
      message: The message string

    Returns:
      TurbiniaRequest|None: Returns the valid object, or None if there are
    decoding failures.
    """

    request = TurbiniaRequest()
    try:
      request.from_json(message)
    except TurbiniaException as exception:
      log.error(f'Error decoding message: {str(exception):s}')
      return None

    return request

  def send_message(self, message):
    """Enqueue a message.

    Args:
      message: The message to send.
    """

    raise NotImplementedError

  def send_request(self, request):
    """Send a TurbiniaRequest to the server.

    Args:
      request: the TurbiniaRequest to send
    """

    self.send_message(request.to_json())
