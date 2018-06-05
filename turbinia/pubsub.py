# -*- coding: utf-8 -*-
# Copyright 2016 Google Inc.
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
"""Google PubSub Listener for requests to Turbinia to process evidence."""

from __future__ import unicode_literals

import copy
import json
import logging
import Queue
import uuid

from google.cloud import pubsub

import celery
import kombu
from amqp.exceptions import ChannelError

# Turbinia
from turbinia import config
from turbinia import evidence
from turbinia import TurbiniaException

log = logging.getLogger('turbinia')


class TurbiniaRequest(object):
  """An object to request evidence to be processed.

  Attributes:
    request_id: A client specified ID for this request.
    recipe: Recipe to use when processing this request.
    context: A Dict of context data to be passed around with this request.
    evidence: A list of Evidence objects.
  """

  def __init__(
      self, request_id=None, recipe=None, context=None, evidence_=None):
    """Initialization for TurbiniaRequest."""
    self.request_id = request_id if request_id else uuid.uuid4().hex
    self.recipe = recipe
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


class TurbiniaCelery(object):
  """Celery app object.

  Attributes:
    app (Celery): The Celery app itself.
    _fexec: Lets us initialize the Celery task after configuring the app, since
        the Celery 'app.task' decorator is unknown before initialization.
    fexec (function, args, kwargs): Celery task, which can run functions
        without needing to pre-register them (similar to PSQ). Takes in a
        function name, as well as any arguments (named or otherwise). All
        workers must have this function defined.
  """

  def __init__(self):
    """Celery configurations."""
    self.app = None
    self.fexec = None

  def _fexec(self):
    """Closure used to pass functions to workers."""
    @self.app.task(name='fexec')
    def fexec(f, *args, **kwargs):
      """Lets us pass in an arbitrary function without Celery annotations"""
      return f(*args, **kwargs)
    return fexec

  def setup(self):
    """Set up Celery"""
    config.LoadConfig()
    self.app = celery.Celery(
        'turbinia',
        broker=config.CELERY_BROKER,
        backend=config.CELERY_BACKEND
    )
    self.app.conf.update(
        task_default_queue=config.INSTANCE_ID,
        event_serializer='pickle',
        result_serializer='pickle',
        task_serializer='pickle',
        accept_content=['pickle'],
        # TODO(ericzinnikas): Without task_acks_late Celery workers will start
        # on one task and prefetch another (i.e. can result in 1 worker getting
        # 2 plaso jobs while another worker is free). But enabling this causes
        # problems with certain Celery brokers (duplicated work).
        task_acks_late=False,
        task_track_started=True,
        worker_concurrency=1,
        worker_prefetch_multiplier=1,
    )
    self.fexec = self._fexec()


class TurbiniaKombu(object):
  """Queue object for receiving evidence messages.

  Attributes:
    queue (Kombu.SimpleBuffer): evidence queue.
  """

  def __init__(self, routing_key):
    """Kombu config."""
    self.queue = None
    self.routing_key = routing_key

  def setup(self):
    """Set up Kombu SimpleBuffer"""
    config.LoadConfig()
    conn = kombu.Connection(config.KOMBU_BROKER)
    if config.KOMBU_DURABLE:
      self.queue = conn.SimpleQueue(name=self.routing_key)
    else:
      self.queue = conn.SimpleBuffer(name=self.routing_key)

  def check_messages(self):
    """See if we have any messages in the queue.

    Returns:
      list[TurbiniaRequest]: all evidence requests.
    """
    results = []
    while True:
      try:
        message = self.queue.get(block=False)
        results.append(message.payload)
        if self.queue.queue.durable:
          message.ack()
      except Queue.Empty:
        break
      except ChannelError:
        break
    log.debug('Received {0:d} messages'.format(len(results)))
    return [self._validate_message(result)
            for result in results
            if self._validate_message(result)]

  def send_message(self, message):
    """Enqueues a message with Kombu"""
    data = message.encode('utf-8')
    self.queue.put(data)
    log.info('Sent message to queue')

  def send_request(self, request):
    """Sends a TurbiniaRequest request"""
    self.send_message(request.to_json())

  def _validate_message(self, message):
    """Validates pubsub messages and returns them as a new TurbiniaRequest obj.

    Args:
      message: PubSub message string

    Returns:
      A TurbiniaRequest object or None if there are decoding failures.
    """
    request = TurbiniaRequest()
    try:
      request.from_json(message)
    except TurbiniaException as e:
      log.error('Error decoding message: {0:s}'.format(str(e)))
      return None

    return request


class TurbiniaPubSub(object):
  """PubSub client object for Google Cloud.

  Attributes:
    topic: The pubsub topic object
    topic_name: The pubsub topic name
    subscription: The pubsub subscription object
  """

  def __init__(self, topic_name):
    """Initialization for PubSubClient."""
    self.topic_name = topic_name
    self.topic = None
    self.subscription = None

  def setup(self):
    """Set up the client."""
    config.LoadConfig()
    client = pubsub.Client(project=config.PROJECT)
    self.topic = client.topic(self.topic_name)
    log.debug('Connecting to PubSub Subscription on {0:s}'.format(
        self.topic_name))
    self.subscription = self.topic.subscription(self.topic_name)

  def _validate_message(self, message):
    """Validates pubsub messages and returns them as a new TurbiniaRequest obj.

    Args:
      message: PubSub message string

    Returns:
      A TurbiniaRequest object or None if there are decoding failures.
    """
    request = TurbiniaRequest()
    try:
      request.from_json(message)
    except TurbiniaException as e:
      log.error('Error decoding pubsub message: {0:s}'.format(str(e)))
      return None

    return request

  def check_messages(self):
    """Checks for pubsub messages.

    Returns:
      A list of any TurbiniaRequest objects received, else an empty list
    """
    results = self.subscription.pull(return_immediately=True)
    log.debug('Recieved {0:d} pubsub messages'.format(len(results)))

    ack_ids = []
    requests = []
    for ack_id, message in results:
      data = message.data
      log.info('Processing PubSub Message {0:s}'.format(message.message_id))
      log.debug('PubSub Message body: {0:s}'.format(data))

      request = self._validate_message(data)
      if request:
        requests.append(request)
        ack_ids.append(ack_id)
      else:
        log.error('Error processing PubSub message: {0:s}'.format(data))

    if results:
      self.subscription.acknowledge(ack_ids)

    return requests

  def send_message(self, message):
    """Send a pubsub message.

    message: The message to send.
    """
    data = message.encode('utf-8')
    msg_id = self.topic.publish(data)
    log.info(
        'Published message {0:s} to topic {1:s}'.format(
            msg_id, self.topic_name))

  def send_request(self, request):
    """Sends a TurbiniaRequest message.

    Args:
      request: A TurbiniaRequest object.
    """
    self.send_message(request.to_json())
