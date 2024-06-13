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
"""Celery app and Kombu queue classes.

Handles worker communication and new evidence requests.
"""

# fix celery naming collision (this file vs. module)
from __future__ import absolute_import

import logging
import celery
import kombu

from kombu.exceptions import OperationalError
from amqp.exceptions import ChannelError

from turbinia import config
from turbinia.message import TurbiniaMessageBase

log = logging.getLogger(__name__)


class TurbiniaCelery:
  """Celery app object.

  Attributes:
    app (Celery): The Celery app itself.
  """

  def __init__(self):
    """Celery configurations."""
    self.app = None

  def setup(self):
    """Set up Celery"""
    config.LoadConfig()
    self.app = celery.Celery(
        'turbinia', broker=config.CELERY_BROKER, backend=config.CELERY_BACKEND)
    self.app.conf.update(
        broker_connection_retry_on_startup=True,
        task_default_queue=config.INSTANCE_ID,
        accept_content=['json'],
        worker_cancel_long_running_tasks_on_connection_loss=True,
        worker_concurrency=1,
        worker_prefetch_multiplier=1,
    )


class TurbiniaKombu(TurbiniaMessageBase):
  """Queue object for receiving evidence messages.

  Attributes:
    queue (Kombu.SimpleBuffer|Kombu.SimpleQueue): evidence queue.
  """

  def __init__(self, routing_key):
    """Kombu config."""
    self.queue = None
    self.routing_key = routing_key

  def setup(self):
    """Set up Kombu SimpleBuffer"""
    config.LoadConfig()
    conn = kombu.Connection(
        config.KOMBU_BROKER, transport_options={
            'socket_timeout': 10,
            'socket_keepalive': True
        })
    if config.KOMBU_DURABLE:
      self.queue = conn.SimpleQueue(name=self.routing_key)
    else:
      self.queue = conn.SimpleBuffer(name=self.routing_key)

  def check_messages(self):
    """See if we have any messages in the queue.

    Returns:
      list[TurbiniaRequest]: all evidence requests.
    """
    requests = []
    while True:
      try:
        message = self.queue.get(block=False)
        request = self._validate_message(message.payload)
        if request:
          requests.append(request)
          if self.queue.queue.durable:
            message.ack()
      except self.queue.Empty:
        break
      except ChannelError:
        break
      except OperationalError as exception:
        log.warning(
            'Caught recoverable message transport connection error when ' +
            f'fetching from queue: {exception!s}')
        break

    if len(requests):
      log.debug(f'Received {len(requests):d} messages')
    return requests

  def send_message(self, message):
    """Enqueues a message with Kombu"""
    data = message.encode('utf-8')
    self.queue.put(data)
    log.info('Sent message to queue')
