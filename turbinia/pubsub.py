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

from google.cloud import pubsub

# Turbinia
from turbinia import config
from turbinia.message import TurbiniaMessageBase

log = logging.getLogger('turbinia')


class TurbiniaPubSub(TurbiniaMessageBase):
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

  def check_messages(self):
    """Checks for pubsub messages.

    Returns:
      A list of any TurbiniaRequest objects received, else an empty list
    """
    results = self.subscription.pull(return_immediately=True)

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

    log.debug('Recieved {0:d} pubsub messages'.format(len(requests)))
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
