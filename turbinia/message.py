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

from __future__ import unicode_literals

import codecs
import copy
import json
import uuid

import six

import logging

from turbinia import evidence
from turbinia import TurbiniaException

log = logging.getLogger('turbinia')


class TurbiniaRequest:
  """An object to request evidence to be processed.

  Attributes:
    request_id(str): A client specified ID for this request.
    group_id(str): A client specified group id for this request.
    requestor(str): The username of who made the request.
    recipe(dict): Recipe to use when processing this request.
    context(dict): A Dict of context data to be passed around with this request.
    evidence(list): A list of Evidence objects.
  """

  def __init__(
      self, request_id=None, group_id=None, requester=None, recipe=None,
      context=None, evidence_=None):
    """Initialization for TurbiniaRequest."""
    self.request_id = request_id if request_id else uuid.uuid4().hex
    self.group_id = group_id if group_id else uuid.uuid4().hex
    self.requester = requester if requester else 'user_unspecified'
    self.recipe = recipe if recipe else {'globals': {}}
    self.context = context if context else {}
    self.evidence = evidence_ if evidence_ else []
    self.type = self.__class__.__name__

  def to_json(self):
    """Convert object to JSON.

    Returns:
      A JSON serialized object.
    """
    serializable = copy.deepcopy(self.__dict__)
    serializable['evidence'] = [x.serialize() for x in serializable['evidence']]

    try:
      serialized = json.dumps(serializable)
    except TypeError as e:
      msg = (
          'JSON serialization of TurbiniaRequest object {0:s} failed: '
          '{1:s}'.format(self.type, str(e)))
      raise TurbiniaException(msg)

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
    except ValueError as e:
      raise TurbiniaException(
          'Can not load json from string {0:s}'.format(str(e)))

    if obj.get('type', None) != self.type:
      raise TurbiniaException(
          'Deserialized object does not have type of {0:s}'.format(self.type))

    obj['evidence'] = [evidence.evidence_decode(e) for e in obj['evidence']]
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
    except TurbiniaException as e:
      log.error('Error decoding message: {0:s}'.format(str(e)))
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
