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

import logging
from Queue import Queue

from google.cloud import pubsub

# Turbinia
from turbinia import config
from turbinia.message import TurbiniaMessageBase

log = logging.getLogger('turbinia')


class TurbiniaPubSub(TurbiniaMessageBase):
  """PubSub client object for Google Cloud.

  Attributes:
    _queue: A Queue object for storing pubsub messages
    topic_name (str): The full pubsub topic name
    topic_subpath (str): The partial name of the last
    subscriber: The pubsub subscriber client object
    publisher: The pubsub publisher client object
    subscription: The pubsub subscription object
  """

  def __init__(self, topic_subpath):
    """Initialization for PubSubClient."""
    self._queue = Queue()
    self.publisher = None
    self.subscriber = None
    self.subscription = None
    self.subscription_name = None
    self.topic_name = None
    self.topic_subpath = topic_subpath

  def setup_publisher(self):
    """Set up the pubsub publisher client."""
    config.LoadConfig()
    print "DEBUG: in setup_publisher()"
    self.publisher = pubsub.PublisherClient()
    self.topic_name = self.publisher.topic_path(
        config.PROJECT, self.topic_subpath)
    log.debug('Setup PubSub publisher {0:s}'.format(self.topic_name))

  def setup_subscriber(self):
    """Set up the pubsub subscriber client."""
    config.LoadConfig()
    self.subscriber = pubsub.SubscriberClient()
    self.subscription_name = self.subscriber.subscription_path(
        config.PROJECT, self.topic_subpath)

    log.debug('Setup PubSub Subscription {0:s}'.format(
        self.subscription_name))
    self.subscription = self.subscriber.subscribe(self.subscription_name)
    self.subscription.open(self._callback)

  def _callback(self, message):
    """Callback function that places messages in the queue.

    Args:
      message: A pubsub message object
    """
    log.debug('Recieved pubsub message: {0:s}'.format(message.data))
    message.ack()
    self._queue.put(message)

  def check_messages(self):
    """Checks for pubsub messages.

    Returns:
      A list of any TurbiniaRequest objects received, else an empty list
    """
    requests = []
    for _ in xrange(self._queue.qsize()):
      message = self._queue.get()
      data = message.data
      log.info('Processing PubSub message {0:s}'.format(message.message_id))
      log.debug('PubSub message body: {0:s}'.format(data))

      request = self._validate_message(data)
      if request:
        requests.append(request)
      else:
        log.error('Error processing PubSub message: {0:s}'.format(data))

    return requests

  def send_message(self, message):
    """Send a pubsub message.

    message: The message to send.
    """
    data = message.encode('utf-8')
    future = self.publisher.publish(self.topic_name, data)
    msg_id = future.result()
    log.info('Published message {0:s} to topic {1:s}'.format(
        msg_id, self.topic_name))

  def send_request(self, request):
    """Sends a TurbiniaRequest message.

    Args:
      request: A TurbiniaRequest object.
    """
    self.send_message(request.to_json())
