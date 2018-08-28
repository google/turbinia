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
from __future__ import unicode_literals

import logging

from six.moves import queue

import celery
import kombu
from amqp.exceptions import ChannelError

from turbinia import config
from turbinia.message import TurbiniaMessageBase

log = logging.getLogger('turbinia')


class TurbiniaCelery(object):
  """Celery app object.

  Attributes:
    app (Celery): The Celery app itself.
  """

  def __init__(self):
    """Celery configurations."""
    self.app = None
    self.fexec = None

  def fexec(f, *args, **kwargs):
    # pylint: disable=no-self-argument,method-hidden
    """Placeholder function, overwritten with the _fexec closure once setup()
    is called. Once overwritten, will call the specified function with
    whichever arguments you pass it.

    Arguments:
      f (function): an arbitrary function
      args: any positional arguments to be passsed to the function
      kwargs: any keyword arguments to be passed to the function
    """
    raise NotImplementedError

  def _fexec(self):
    """Closure used to pass functions to workers. We use this instead of having
    to annotate each individual TurbiniaTask with the Celery @app.task
    decorator.

    Returns:
      function: the fexec() function.
    """
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
        # TODO(ericzinnikas): pickle is not secure, we need to replace it with
        # the default json serializer, but need to figure out how to register
        # the TurbiniaTask objects with Celery
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
    requests = []
    while True:
      try:
        message = self.queue.get(block=False)
        request = self._validate_message(message.payload)
        if request:
          requests.append(request)
          if self.queue.queue.durable:
            message.ack()
      except queue.Empty:
        break
      except ChannelError:
        break

    log.debug('Received {0:d} messages'.format(len(requests)))
    return requests

  def send_message(self, message):
    """Enqueues a message with Kombu"""
    data = message.encode('utf-8')
    self.queue.put(data)
    log.info('Sent message to queue')
