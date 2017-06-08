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
  tr = pubsub.TurbiniaRequest(request_id=u'deadbeef', context={'kw': [1, 2]})
  e = evidence.RawDisk(
      name=u'My Evidence', local_path=u'/tmp/foo', mount_path=u'/mnt/foo')
  tr.evidence.append(e)
  return tr


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
    tr = getTurbiniaRequest()
    tr_json = tr.to_json()
    self.assertTrue(isinstance(tr_json, str))

    # Create a new Turbinia Request object to load our results into
    tr_new = pubsub.TurbiniaRequest()
    tr_new.from_json(tr_json)

    self.assertTrue(isinstance(tr_new, pubsub.TurbiniaRequest))
    self.assertTrue(tr_new.context['kw'][1], 2)
    self.assertTrue(tr_new.request_id, u'deadbeef')
    self.assertTrue(isinstance(tr_new.evidence[0], evidence.RawDisk))
    self.assertEqual(tr_new.evidence[0].name, u'My Evidence')

  def testTurbiniaRequestSerializationBadData(self):
    """Tests that TurbiniaRequest will raise error on non-json data."""
    tr_new = pubsub.TurbiniaRequest()
    self.assertRaises(TurbiniaException, tr_new.from_json, 'non-json-data')

  def testTurbiniaRequestSerializationBadJSON(self):
    """Tests that TurbiniaRequest will raise error on wrong JSON object."""
    e = evidence.RawDisk(name=u'My Evidence', local_path=u'/tmp/foo')
    e_json = e.to_json()
    self.assertTrue(isinstance(e_json, str))

    tr_new = pubsub.TurbiniaRequest()
    # Try to load serialization RawDisk() into a TurbiniaRequest, which should
    # error because this is not the correct type.
    self.assertRaises(TurbiniaException, tr_new.from_json, e_json)


class TestTurbiniaPubSub(unittest.TestCase):
  """Test turbinia.pubsub module."""

  def setUp(self):
    tr = getTurbiniaRequest()
    self.pubsub = pubsub.TurbiniaPubSub(u'fake_topic')
    results = MockPubSubResults(
        ack_id=u'1234', message=MockPubSubMessage(tr.to_json(), u'msg id'))
    self.pubsub.subscription = mock.MagicMock()
    self.pubsub.subscription.pull.return_value = results

  def testCheckMessages(self):
    """Test check_messages to make sure it returns the expected results."""
    results = self.pubsub.check_messages()
    self.assertTrue(len(results) == 1)
    tr_new = results[0]

    # Make sure that the TurbiniaRequest object is as expected
    self.assertTrue(isinstance(tr_new, pubsub.TurbiniaRequest))
    self.assertTrue(tr_new.context['kw'][1], 2)
    self.assertTrue(tr_new.request_id, u'deadbeef')
    self.assertTrue(isinstance(tr_new.evidence[0], evidence.RawDisk))
    self.assertEqual(tr_new.evidence[0].name, u'My Evidence')

    # Make sure that the test message was acknowledged
    self.pubsub.subscription.acknowledge.assert_called_with([u'1234'])

  def testBadCheckMessages(self):
    """Test check_messages returns empty list for an invalid message."""
    results = MockPubSubResults(
        ack_id=u'2345', message=MockPubSubMessage(u'non-json-data', u'msg id2'))
    self.pubsub.subscription.pull.return_value = results

    self.assertListEqual(self.pubsub.check_messages(), [])

  def testSendMessage(self):
    """Test sending a message."""
    self.pubsub.topic = mock.MagicMock()
    self.pubsub.send_message(u'test message text')
    self.pubsub.topic.publish.assert_called_with(u'test message text')
