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
"""Google PubSub Client."""

import base64
import httplib2
import logging

import json

# Google API
from googleapiclient import discovery
from googleapiclient import errors as google_errors
from googleapiclient import http as storage_http
from oauth2client import client as oauth2client

# Turbinia
from turbinia import config

# PubSub Message types
[
  TASKNEW,
  TASKABORT,
  TASKSTART,
  TASKUPDATE,
  TASKSTOP,
  WORKERSTART,
  WORKERUPDATE,
  WORKERSTOP,
] = xrange(8)


class GoogleCloudClient(object):

  def __init__(self, service):
    self.service = service
    self.client = None

  def _client_setup(self):
    """Creates an API client for talking to Google Cloud.

    Returns:
        A client object for interacting with the cloud service.
    """
    logging.info(u'Creating API client for service: {0:s}'.format(self.service))
    credentials = oauth2client.GoogleCredentials.get_application_default()
    http = httplib2.Http()
    credentials.authorize(http)
    self.client = discovery.build(self.service, 'v1', http=http)
    return self.client


class PubSubClient(GoogleCloudClient):
  def __init__(self, topic):
    self.topic = topic
    super(PubSubClient, self).__init__(u'pubsub')
    config.LoadConfig()
    self.subscription = u'projects/{0:s}/subscriptions/{1:s}'.format(
        config.PROJECT, self.topic)

  def _setup(self):
    self._client_setup()

  def _validate_message(self, message):
    """Validates pubsub messages to ensure required fields are available.

    Args:
      message: dict of pubsub message

    Returns:
      Bool indicating whether message is properly validated
    """
    required_fields = {
        # Turbinia to workers
        TASKNEW: [u'task_id', u'job_id', u'evidence'],
        TASKABORT: [u'task_id', u'job_id'],
        # Tasks to Turbinia
        TASKSTART: [u'task_id', u'job_id'],
        TASKUPDATE: [u'task_id', u'job_id', u'update_text'],
        TASKSTOP: [u'task_id', u'job_id', u'result'],
        # Workers to Turbinia
        WORKERSTART: [u'worker_id'],
        WORKERUPDATE: [u'worker_id', u'update_text'],
        WORKERSTOP: [u'worker_id'],
    }

    if not message.has_key(u'message_type'):
      logging.error(u'Message has no message_type: {0:s}'.format(str(message)))
      return False

    for field in required_fields.get(message[u'message_type'], []):
      if not message.has_key(field):
        logging.error(u'Message type {0:s} must have field {1:s}: {2:s}'.format(
            message.get(u'message_type'), field, str(message)))
        return False

    return True

  def check_message(self):
    """Checks for a pubsub message.

    Returns:
      Data dict if message is received, else None
    """
    data = None
    body = {
        u'returnImmediately': False,
        u'maxMessages': 1,
    }

    resp = self.client.projects().subscriptions().pull(
        subscription=self.subscription, body=body).execute()
    received_messages = resp.get(u'receivedMessages')
    if received_messages is not None:
      ack_ids = []
      received_message = received_messages[0]
      pubsub_message = received_message.get(u'message')
      if pubsub_message:
        logging.info(u'PubSub message received')
        # Process messages
        data = base64.b64decode(str(pubsub_message.get(u'data')))
        try:
          data = json.loads(data)
          logging.info(u'Message body: {0:s}'.format(data))
        except (ValueError, KeyError) as e:
          logging.error(u'Error processing message: {0:s}'.format(e))

        # Get the message's ack ID
        ack_ids.append(received_message.get(u'ackId'))

        # Create a POST body for the acknowledge request
        ack_body = {u'ackIds': ack_ids}

        # Acknowledge the message.
        self.client.projects().subscriptions().acknowledge(
            self.subscription=subscription, body=ack_body).execute()

    if not self._validate_message(data):
      logging.error('Error processing invalid message: {0:s}'.format(data))

    return data

  # TODO(aarontp): fill in
  def send_message(self, message):
    pass
