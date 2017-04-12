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
"""Turbinia Evidence objects."""

import json


# TODO(aarontp): Add serialization so we can pass these in messages
class Evidence(object):

  def __init__(self, name=None, description=None, local_path=None):
    self.name = name
    self.local_path = local_path
    self.description = description

    # List of jobs that have processed this evidence
    self.processed_by = []
    self.type = self.__class__.__name__

  def __str__(self):
    return u'{0:s} {1:s}'.format(self.name, self.type)


class RawDisk(Evidence):
  pass


class EncryptedDisk(Evidence):
  """Encrypted disk file evidence."""

  def __init__(self, encryption_type=None, encryption_key=None,
               unencrypted_path=None, *args, **kwargs):
    self.encryption_type = encryption_type
    self.encryption_key = encryption_key
    # self.local_path will be the encrypted path
    self.unencrypted_path = unencrypted_path
    super(EncryptedDisk, self).__init__(*args, **kwargs)


class GoogleCloudDisk(Evidence):

  def __init__(self, project=None, zone=None, device_name=None,
               cloud_path=None, *args, **kwargs):
    self.project = project
    self.zone = zone
    self.device_name = device_name
    self.cloud_path = cloud_path
    super(GoogleCloudDisk, self).__init__(*args, **kwargs)


class PlasoFile(Evidence):
  """Plaso output file evidence."""

  def __init__(self, plaso_version=None, *args, **kwargs):
    self.plaso_version = plaso_version
    super(PlasoFile, self).__init__(*args, **kwargs)
