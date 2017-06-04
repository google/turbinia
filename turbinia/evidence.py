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

from turbinia import TurbiniaException


class Evidence(object):
  """Evidence object for processing.

  In most cases, these objects will just contain metadata about the actual
  evidence.

  Attributes:
    name: Name of evidence.
    description: Description of evidence.
    source: String indicating where evidence came from (including tool version
            that created it, if appropriate).
    local_path: A string of the local_path to the evidence.
    tags: dict of extra tags assocated with this evidence.
  """

  def __init__(
      self,
      name=None,
      description=None,
      source=None,
      local_path=None,
      tags=None):
    """Initialization for Evidence."""
    self.name = name
    self.description = description
    self.source = source
    self.local_path = local_path
    self.tags = tags if tags else {}

    # List of jobs that have processed this evidence
    self.processed_by = []
    self.type = self.__class__.__name__

  def __str__(self):
    return u'{0:s} {1:s}'.format(self.type, self.name)

  def to_json(self):
    """Convert object to JSON.

    Returns:
      A JSON serialized string of the current object.

    Raises:
      TurbiniaException: If serialization error occurs.
    """
    serialized = None
    try:
      serialized = json.dumps(self.__dict__)
    except TypeError as e:
      msg = 'JSON serialization of evidence object {0:s} failed: {1:s}'.format(
          self.type, str(e))
      raise TurbiniaException(msg)

    return serialized


class RawDisk(Evidence):
  """Evidence object for Disk based evidence.

  Attributes:
    mount_path: The mount path for this disk (if any).
    size:  The size of the disk in bytes.
  """

  def __init__(self, mount_path=None, size=None, *args, **kwargs):
    """Initialization for raw disk evidence object."""
    self.mount_path = mount_path
    self.size = size
    super(RawDisk, self).__init__(*args, **kwargs)


class EncryptedDisk(RawDisk):
  """Encrypted disk file evidence.

  Attributes:
    encryption_type: The type of encryption used, e.g. FileVault or Bitlocker.
    encryption_key: A string of the encryption key used for this disk.
    unencrypted_path: A string to the unencrypted local path
  """

  def __init__(
      self,
      encryption_type=None,
      encryption_key=None,
      unencrypted_path=None,
      *args,
      **kwargs):
    """Initialization for Encrypted disk evidence objects."""
    # TODO(aarontp): Make this an enum, or limited list
    self.encryption_type = encryption_type
    self.encryption_key = encryption_key
    # self.local_path will be the encrypted path
    self.unencrypted_path = unencrypted_path
    super(EncryptedDisk, self).__init__(*args, **kwargs)


class GoogleCloudDisk(RawDisk):
  """Evidence object for Google Cloud Disks.

  Attributes:
    project: The cloud project name this disk is associated with.
    zone: The geographic zone.
    disk_name: The cloud disk name.
    type: The type of cloud disk.
  """

  def __init__(
      self,
      project=None,
      zone=None,
      disk_name=None,
      type_=None,
      *args,
      **kwargs):
    """Initialization for Google Cloud Disk."""
    self.project = project
    self.zone = zone
    self.disk_name = disk_name
    self.type = type_
    super(GoogleCloudDisk, self).__init__(*args, **kwargs)


class PlasoFile(Evidence):
  """Plaso output file evidence.

  Attributes:
    plaso_version: The version of plaso that processed this file.
  """

  def __init__(self, plaso_version=None, *args, **kwargs):
    """Initialization for Plaso File evidence."""
    self.plaso_version = plaso_version
    super(PlasoFile, self).__init__(*args, **kwargs)


# TODO(aarontp): Find a way to integrate this into TurbiniaTaskResult instead.
class ReportText(Evidence):
  """Text data for general reporting."""

  def __init__(self, text_data=None, *args, **kwargs):
    self.text_data = text_data
    super(ReportText, self).__init__(*args, **kwargs)
