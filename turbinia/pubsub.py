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

import base64
import codecs
import logging

from six.moves import queue
from six.moves import xrange

from google.cloud import exceptions
from google.cloud import pubsub
from googleapiclient.errors import HttpError
import libcloudforensics.providers.gcp.internal.common as gcp_common

from turbinia import config
from turbinia import TurbiniaException
from turbinia.message import TurbiniaMessageBase

log = logging.getLogger('turbinia')


class TurbiniaPubSub(TurbiniaMessageBase):
  """PubSub client object for Google Cloud.

  Attributes:
    _queue: A Queue object for storing pubsub messages
    pubsub_api_client: The pubsub API client object
    subscriber: The pubsub subscriber client object
    subscription: The pubsub subscription object
    topic_name (str): The pubsub topic name
    topic_path (str): The full path of the pubsub topic
  """

  def __init__(self, topic_name):
    """Initialization for PubSubClient."""
    self._queue = queue.Queue()
    self.pubsub_api_client = None
    self.subscriber = None
    self.subscription = None
    self.topic_name = topic_name
    self.topic_path = None

  def setup(self):
    """Set up the pubsub clients."""
    self.setup_publisher()
    self.setup_subscriber()

  def setup_publisher(self):
    """Set up the pubsub publisher."""
    config.LoadConfig()
    # the publisher we will use the pubsub client in googleapiclient.discovery
    # for more information on using the APIs, see
    # https://cloud.google.com/pubsub/docs/reference/rest
    self.pubsub_api_client = gcp_common.CreateService('pubsub', 'v1')
    self.topic_path = 'projects/{0:s}/topics/{1:s}'.format(
        config.TURBINIA_PROJECT, self.topic_name)
    try:
      log.debug('Trying to create pubsub topic {0:s}'.format(self.topic_path))
      topics_client = self.pubsub_api_client.projects().topics()
      # the ExecuteRequest takes API URI, method name as string and parameters
      # as a dict, it executes the API call, handles paging and return response.
      gcp_common.ExecuteRequest(
          topics_client, 'create', {'name': self.topic_path})
    except HttpError as exception:
      if exception.resp.status == 409:
        log.debug('PubSub topic {0:s} already exists.'.format(self.topic_path))
      else:
        raise TurbiniaException(
            'Unknown error occurred when creating Topic:'
            ' {0!s}'.format(exception), __name__) from exception
    log.debug('Setup PubSub publisher at {0:s}'.format(self.topic_path))

  def setup_subscriber(self):
    """Set up the pubsub subscriber."""
    config.LoadConfig()
    self.subscriber = pubsub.SubscriberClient()
    subscription_path = self.subscriber.subscription_path(
        config.TURBINIA_PROJECT, self.topic_name)
    if not self.topic_path:
      self.topic_path = self.subscriber.topic_path(
          config.TURBINIA_PROJECT, self.topic_name)
    try:
      log.debug(
          'Trying to create subscription {0:s} on topic {1:s}'.format(
              subscription_path, self.topic_path))
      self.subscriber.create_subscription(subscription_path, self.topic_path)
    except exceptions.Conflict:
      log.debug('Subscription {0:s} already exists.'.format(subscription_path))

    log.debug('Setup PubSub Subscription {0:s}'.format(subscription_path))
    self.subscription = self.subscriber.subscribe(
        subscription_path, self._callback)

  def _callback(self, message):
    """Callback function that places messages in the queue.

    Args:
      message: A pubsub message object
    """
    data = codecs.decode(message.data, 'utf-8')
    log.debug('Received pubsub message: {0:s}'.format(data))
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
    base64_data = base64.b64encode(message.encode('utf-8'))
    request_body = {
        "messages": [{
            "data":
                base64_data.decode('utf-8')  # base64 encoded string
        }]
    }
    publish_client = self.pubsub_api_client.projects().topics()
    response = gcp_common.ExecuteRequest(
        publish_client, 'publish', {
            'topic': self.topic_path,
            'body': request_body
        })
    # Safe to unpack since response is unpaged.
    if not response[0]['messageIds']:
      raise TurbiniaException(
          'Message {0:s} was not published to topic {1:s}'.format(
              message, self.topic_path))
    msg_id = response[0]['messageIds'][0]
    log.info(
        'Published message {0!s} to topic {1!s}'.format(
            msg_id, self.topic_name))

  def send_request(self, request):
    """Sends a TurbiniaRequest message.

    Args:
      request: A TurbiniaRequest object.
    """
    self.send_message(request.to_json())
