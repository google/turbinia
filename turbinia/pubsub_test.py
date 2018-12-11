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
"""Tests for Turbinia pubsub module."""

from __future__ import unicode_literals

import unittest

import mock

from six.moves import queue

from turbinia import evidence
from turbinia import pubsub
from turbinia import message
from turbinia import celery
from turbinia import TurbiniaException


def getTurbiniaRequest():
  """Get a Turbinia Request object with valid evidence attached.

  Returns:
    TurbiniaRequest object.
  """
  request = message.TurbiniaRequest(
      request_id='deadbeef', context={'kw': [1, 2]})
  rawdisk = evidence.RawDisk(
      name='My Evidence', local_path='/tmp/foo', mount_path='/mnt/foo')
  request.evidence.append(rawdisk)
  return request


class MockPubSubMessage(object):
  """This is a mock of a PubSub message."""

  def __init__(self, data='fake data', message_id='12345'):
    self.data = data if data else ''
    self.message_id = message_id


class TestTurbiniaRequest(unittest.TestCase):
  """Test TurbiniaRequest class."""

  def testTurbiniaRequestSerialization(self):
    """Test that TurbiniaRequests serializes/unserializes."""
    request = getTurbiniaRequest()
    request_json = request.to_json()
    self.assertTrue(isinstance(request_json, str))

    # Create a new Turbinia Request object to load our results into
    request_new = message.TurbiniaRequest()
    request_new.from_json(request_json)

    self.assertTrue(isinstance(request_new, message.TurbiniaRequest))
    self.assertTrue(request_new.context['kw'][1], 2)
    self.assertTrue(request_new.request_id, 'deadbeef')
    self.assertTrue(isinstance(request_new.evidence[0], evidence.RawDisk))
    self.assertEqual(request_new.evidence[0].name, 'My Evidence')

  def testTurbiniaRequestSerializationBadData(self):
    """Tests that TurbiniaRequest will raise error on non-json data."""
    request_new = message.TurbiniaRequest()
    self.assertRaises(TurbiniaException, request_new.from_json, 'non-json-data')

  def testTurbiniaRequestSerializationBadJSON(self):
    """Tests that TurbiniaRequest will raise error on wrong JSON object."""
    rawdisk = evidence.RawDisk(name='My Evidence', local_path='/tmp/foo')
    rawdisk_json = rawdisk.to_json()
    self.assertTrue(isinstance(rawdisk_json, str))

    request_new = message.TurbiniaRequest()
    # Try to load serialization RawDisk() into a TurbiniaRequest, which should
    # error because this is not the correct type.
    self.assertRaises(TurbiniaException, request_new.from_json, rawdisk_json)


class TestTurbiniaPubSub(unittest.TestCase):
  """Test turbinia.pubsub module."""

  def setUp(self):
    request = getTurbiniaRequest()
    self.pubsub = pubsub.TurbiniaPubSub('fake_topic')
    pub_sub_message = MockPubSubMessage(request.to_json(), 'msg id')
    # pylint: disable=protected-access
    self.pubsub._queue.put(pub_sub_message)
    self.pubsub.topic_path = 'faketopicpath'

  def testCheckMessages(self):
    """Test check_messages to make sure it returns the expected results."""
    results = self.pubsub.check_messages()
    self.assertTrue(len(results) == 1)
    request_new = results[0]

    # Make sure that the TurbiniaRequest object is as expected
    self.assertTrue(isinstance(request_new, message.TurbiniaRequest))
    self.assertTrue(request_new.context['kw'][1], 2)
    self.assertTrue(request_new.request_id, 'deadbeef')
    self.assertTrue(isinstance(request_new.evidence[0], evidence.RawDisk))
    self.assertEqual(request_new.evidence[0].name, 'My Evidence')

  def testBadCheckMessages(self):
    """Test check_messages returns empty list for an invalid message."""
    pub_sub_message = MockPubSubMessage('non-json-data', 'msg id2')
    # Clear the queue so we can add an invalid message
    # pylint: disable=protected-access
    self.pubsub._queue.get()
    self.pubsub._queue.put(pub_sub_message)

    self.assertListEqual(self.pubsub.check_messages(), [])

  def testSendMessage(self):
    """Test sending a message."""
    self.pubsub.publisher = mock.MagicMock()
    self.pubsub.send_message('test message text')
    self.pubsub.publisher.publish.assert_called_with(
        'faketopicpath', b'test message text')


class TestTurbiniaKombu(unittest.TestCase):
  """Test turbinia.pubsub Kombu module."""

  def setUp(self):
    """Sets up test class."""
    request = getTurbiniaRequest()
    self.kombu = celery.TurbiniaKombu('fake_topic')
    result = mock.MagicMock()
    result.payload = request.to_json()
    self.kombu.queue = mock.MagicMock()
    self.kombu.queue.__len__.return_value = 1
    self.kombu.queue.get.side_effect = [result, queue.Empty('Empty Queue')]

  def testCheckMessages(self):
    """Test check_messages method."""
    results = self.kombu.check_messages()
    self.assertTrue(len(results) == 1)
    request_new = results[0]

    # Make sure that the TurbiniaRequest object is as expected
    self.assertTrue(isinstance(request_new, message.TurbiniaRequest))
    self.assertTrue(request_new.context['kw'][1], 2)
    self.assertTrue(request_new.request_id, 'deadbeef')
    self.assertTrue(isinstance(request_new.evidence[0], evidence.RawDisk))
    self.assertEqual(request_new.evidence[0].name, 'My Evidence')

  def testBadCheckMessages(self):
    """Test check_messages method with non-json data."""
    result = mock.MagicMock()
    result.payload = 'non-json-data'
    self.kombu.queue.get.side_effect = [result, queue.Empty('Empty Queue')]

    self.assertListEqual(self.kombu.check_messages(), [])
