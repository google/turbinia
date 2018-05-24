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

from turbinia import evidence
from turbinia import pubsub
from turbinia import TurbiniaException


def getTurbiniaRequest():
  """Get a Turbinia Request object with valid evidence attached.

  Returns:
    TurbiniaRequest object.
  """
  request = pubsub.TurbiniaRequest(
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


class MockPubSubResults(list):
  """Mock of a PubSub Results list that can contain MockPubSubMessages."""

  def __init__(self, ack_id='54321', message='fake message'):
    super(MockPubSubResults, self).__init__()
    self.append((ack_id, message))


class TestTurbiniaRequest(unittest.TestCase):
  """Test TurbiniaRequest class."""

  def testTurbiniaRequestSerialization(self):
    """Test that TurbiniaRequests serializes/unserializes."""
    request = getTurbiniaRequest()
    request_json = request.to_json()
    self.assertTrue(isinstance(request_json, str))

    # Create a new Turbinia Request object to load our results into
    request_new = pubsub.TurbiniaRequest()
    request_new.from_json(request_json)

    self.assertTrue(isinstance(request_new, pubsub.TurbiniaRequest))
    self.assertTrue(request_new.context['kw'][1], 2)
    self.assertTrue(request_new.request_id, 'deadbeef')
    self.assertTrue(isinstance(request_new.evidence[0], evidence.RawDisk))
    self.assertEqual(request_new.evidence[0].name, 'My Evidence')

  def testTurbiniaRequestSerializationBadData(self):
    """Tests that TurbiniaRequest will raise error on non-json data."""
    request_new = pubsub.TurbiniaRequest()
    self.assertRaises(TurbiniaException, request_new.from_json, 'non-json-data')

  def testTurbiniaRequestSerializationBadJSON(self):
    """Tests that TurbiniaRequest will raise error on wrong JSON object."""
    rawdisk = evidence.RawDisk(name='My Evidence', local_path='/tmp/foo')
    rawdisk_json = rawdisk.to_json()
    self.assertTrue(isinstance(rawdisk_json, str))

    request_new = pubsub.TurbiniaRequest()
    # Try to load serialization RawDisk() into a TurbiniaRequest, which should
    # error because this is not the correct type.
    self.assertRaises(TurbiniaException, request_new.from_json, rawdisk_json)


class TestTurbiniaPubSub(unittest.TestCase):
  """Test turbinia.pubsub module."""

  def setUp(self):
    request = getTurbiniaRequest()
    self.pubsub = pubsub.TurbiniaPubSub('fake_topic')
    results = MockPubSubResults(
        ack_id='1234', message=MockPubSubMessage(request.to_json(), 'msg id'))
    self.pubsub.subscription = mock.MagicMock()
    self.pubsub.subscription.pull.return_value = results

  def testCheckMessages(self):
    """Test check_messages to make sure it returns the expected results."""
    results = self.pubsub.check_messages()
    self.assertTrue(len(results) == 1)
    request_new = results[0]

    # Make sure that the TurbiniaRequest object is as expected
    self.assertTrue(isinstance(request_new, pubsub.TurbiniaRequest))
    self.assertTrue(request_new.context['kw'][1], 2)
    self.assertTrue(request_new.request_id, 'deadbeef')
    self.assertTrue(isinstance(request_new.evidence[0], evidence.RawDisk))
    self.assertEqual(request_new.evidence[0].name, 'My Evidence')

    # Make sure that the test message was acknowledged
    self.pubsub.subscription.acknowledge.assert_called_with(['1234'])

  def testBadCheckMessages(self):
    """Test check_messages returns empty list for an invalid message."""
    results = MockPubSubResults(
        ack_id='2345', message=MockPubSubMessage('non-json-data', 'msg id2'))
    self.pubsub.subscription.pull.return_value = results

    self.assertListEqual(self.pubsub.check_messages(), [])

  def testSendMessage(self):
    """Test sending a message."""
    self.pubsub.topic = mock.MagicMock()
    self.pubsub.send_message('test message text')
    self.pubsub.topic.publish.assert_called_with('test message text')


class TestTurbiniaKombu(unittest.TestCase):
  """Test turbinia.pubsub Kombu module."""

  def setUp(self):
    request = getTurbiniaRequest()
    self.kombu = pubsub.TurbiniaKombu('fake_topic')
    result = mock.MagicMock()
    result.body = request.to_json()
    self.kombu.queue = mock.MagicMock()
    self.kombu.queue.__len__.return_value = 1
    self.kombu.queue.get.return_value = result

  def testCheckMessages(self):
    results = self.kombu.check_messages()
    self.assertTrue(len(results) == 1)
    request_new = results[0]

    # Make sure that the TurbiniaRequest object is as expected
    self.assertTrue(isinstance(request_new, pubsub.TurbiniaRequest))
    self.assertTrue(request_new.context['kw'][1], 2)
    self.assertTrue(request_new.request_id, 'deadbeef')
    self.assertTrue(isinstance(request_new.evidence[0], evidence.RawDisk))
    self.assertEqual(request_new.evidence[0].name, 'My Evidence')

  def testBadCheckMessages(self):
    result = mock.MagicMock()
    result.body = 'non-json-data'
    self.kombu.queue.get.return_value = result

    self.assertListEqual(self.kombu.check_messages(), [])
