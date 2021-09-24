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
"""Tests for Turbinia evidence."""

from __future__ import unicode_literals

import json
import mock
import unittest

from turbinia import evidence
from turbinia import TurbiniaException


class TestEvidence(evidence.Evidence):
  POSSIBLE_STATES = [evidence.EvidenceState.MOUNTED]


class TestTurbiniaEvidence(unittest.TestCase):
  """Test evidence module."""

  def testEvidenceSerialization(self):
    """Test that evidence serializes/unserializes."""
    rawdisk = evidence.RawDisk(name='My Evidence', source_path='/tmp/foo')
    rawdisk_json = rawdisk.to_json()
    self.assertTrue(isinstance(rawdisk_json, str))

    rawdisk_new = evidence.evidence_decode(json.loads(rawdisk_json))
    self.assertIsInstance(rawdisk_new, evidence.RawDisk)
    self.assertEqual(rawdisk_new.name, 'My Evidence')

  def testEvidenceCollectionDeserialization(self):
    """Test that EvidenceCollection deserializes."""
    rawdisk = evidence.RawDisk(name='My Evidence', source_path='/tmp/foo.img')
    collection = evidence.EvidenceCollection()
    collection.name = 'testCollection'
    collection.add_evidence(rawdisk)
    collection_json = collection.to_json()
    self.assertTrue(isinstance(collection_json, str))

    collection_new = evidence.evidence_decode(json.loads(collection_json))
    rawdisk_new = collection_new.collection[0]
    # Make sure that both the collection, and the things in the collection
    # deserializd to the correct types.
    self.assertIsInstance(collection_new, evidence.EvidenceCollection)
    self.assertIsInstance(rawdisk_new, evidence.RawDisk)
    self.assertEqual(collection_new.name, 'testCollection')
    self.assertEqual(rawdisk_new.name, 'My Evidence')
    self.assertEqual(rawdisk_new.source_path, '/tmp/foo.img')

  def testEvidenceCollectionSerialization(self):
    """Test that EvidenceCollection serializes/unserializes."""
    evidence_ = evidence.EvidenceCollection()
    rawdisk = evidence.RawDisk(name='My Evidence', source_path='/tmp/foo.img')
    evidence_.add_evidence(rawdisk)
    serialized_evidence = evidence_.serialize()
    collection_evidence = serialized_evidence['collection'][0]

    self.assertIsInstance(serialized_evidence, dict)
    self.assertEqual(collection_evidence['name'], 'My Evidence')

  def testEvidenceSerializationBadType(self):
    """Test that evidence_decode throws error on non-dict type."""
    self.assertRaises(TurbiniaException, evidence.evidence_decode, [1, 2])

  def testEvidenceSerializationNoTypeAttribute(self):
    """Test that evidence_decode throws error on dict with no type attribute."""
    test = {1: 2, 3: 4}
    self.assertRaises(TurbiniaException, evidence.evidence_decode, test)

  def testEvidenceValidation(self):
    """Test successful evidence validation."""
    rawdisk = evidence.RawDisk(name='My Evidence', source_path='/tmp/foo')
    rawdisk.REQUIRED_ATTRIBUTES = ['name', 'source_path']
    rawdisk.validate()

  def testEvidenceValidationEmptyAttribute(self):
    """Test failed evidence validation with an empty attribute."""
    rawdisk = evidence.RawDisk(name='My Evidence', source_path=None)
    rawdisk.REQUIRED_ATTRIBUTES = ['name', 'source_path']
    self.assertRaises(TurbiniaException, rawdisk.validate)

  def testEvidenceValidationNoAttribute(self):
    """Test failed evidence validation with no attribute."""
    rawdisk = evidence.RawDisk(name='My Evidence', source_path='/tmp/foo')
    rawdisk.REQUIRED_ATTRIBUTES = ['doesnotexist']
    self.assertRaises(TurbiniaException, rawdisk.validate)

  @mock.patch('turbinia.evidence.Evidence._preprocess')
  def testEvidencePreprocess(self, mock_preprocess):
    """Basic test for Evidence.preprocess()."""
    test_evidence = TestEvidence()
    test_evidence.preprocess(
        'task123', required_states=[evidence.EvidenceState.ATTACHED])
    mock_preprocess.assert_called_with(None, [evidence.EvidenceState.ATTACHED])
