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
import os
import sys

from turbinia import TurbiniaException
from turbinia.processors import google_cloud
from turbinia.processors import mount_local


def evidence_decode(evidence_dict):
  """Decode JSON into appropriate Evidence object.

  Args:
    evidence_dict: JSON serializeable evidence object (i.e. a dict post JSON
                   decoding).

  Returns:
    An instantiated Evidence object (or a sub-class of it).

  Raises:
    TurbiniaException: If input is not a dict, does not have a type attribute,
                       or does not deserialize to an evidence object.
  """
  if not isinstance(evidence_dict, dict):
    raise TurbiniaException(
        u'Evidence_dict is not a dictionary, type is {0:s}'.format(
            str(type(evidence_dict))))

  type_ = evidence_dict.get(u'type', None)
  if not type_:
    raise TurbiniaException(
        u'No Type attribute for evidence object [{0:s}]'.format(
            str(evidence_dict)))

  try:
    evidence = getattr(sys.modules[__name__], type_)()
  except AttributeError:
    raise TurbiniaException(
        u'No Evidence object of type {0:s} in evidence module'.format(type_))

  evidence.__dict__ = evidence_dict
  return evidence


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
    tags: dict of extra tags associated with this evidence.
    request_id: The id of the request this evidence came from, if any
  """

  def __init__(
      self,
      name=None,
      description=None,
      source=None,
      local_path=None,
      tags=None,
      request_id=None):
    """Initialization for Evidence."""
    self.description = description
    self.source = source
    self.local_path = local_path
    self.tags = tags if tags else {}
    self.request_id = request_id

    # List of jobs that have processed this evidence
    self.processed_by = []
    self.type = self.__class__.__name__
    self.name = name if name else self.type

  def __str__(self):
    return u'{0:s}:{1:s}:{2:s}'.format(self.type, self.name, self.local_path)

  def serialize(self):
    """Return JSON serializable object."""
    return self.__dict__

  def to_json(self):
    """Convert object to JSON.

    Returns:
      A JSON serialized string of the current object.

    Raises:
      TurbiniaException: If serialization error occurs.
    """
    serialized = None
    try:
      serialized = json.dumps(self.serialize())
    except TypeError as e:
      msg = 'JSON serialization of evidence object {0:s} failed: {1:s}'.format(
          self.type, str(e))
      raise TurbiniaException(msg)

    return serialized

  def preprocess(self):
    """Preprocess this evidence prior to task running.

    This gets run in the context of the local task execution on the worker
    nodes prior to the task itself running.  This can be used to prepare the
    evidence to be processed (e.g. attach a cloud disk, mount a local disk etc).
    """
    pass

  def postprocess(self):
    """Postprocess this evidence after the task runs.

    This gets run in the context of the local task execution on the worker
    nodes after the task has finished.  This can be used to clean-up after the
    evidence is processed (e.g. detach a cloud disk, etc,).
    """
    pass


class Directory(Evidence):
  """Filesystem directory evidence."""
  pass


class RawDisk(Evidence):
  """Evidence object for Disk based evidence.

  Attributes:
    mount_path: The mount path for this disk (if any).
    partition: The partition number to process (if any).
    size:  The size of the disk in bytes.
  """

  def __init__(self, mount_path=None, partition=None, size=None, *args,
               **kwargs):
    """Initialization for raw disk evidence object."""
    self.mount_path = mount_path
    # By default Turbinia will process the entire raw disk, but if a partition
    # is selected it will attempt to process only this partition.
    self.partition = partition
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

  def preprocess(self):
    google_cloud.PreprocessAttachDisk(self)

  def postprocess(self):
    google_cloud.PostprocessDetachDisk(self)


class GoogleCloudDiskRawEmbedded(GoogleCloudDisk):
  """Evidence object for raw disks embedded in Persistent Disks.

  This is for a raw image file that is located in the filesystem of a mounted
  GCP Persistent Disk.  This can be useful if you want to process a raw disk
  image originating from outside cloud, and it is much more performant and
  reliable option than reading it directly from GCS FUSE.

  Attributes:
    embedded_path: The path of the raw disk image inside the Persistent Disk
  """

  def __init__(self, embedded_path=None, *args, **kwargs):
    """Initialization for Google Cloud Disk."""
    self.embedded_path = embedded_path
    super(GoogleCloudDiskRawEmbedded, self).__init__(*args, **kwargs)

  def preprocess(self):
    google_cloud.PreprocessAttachDisk(self)
    mount_local.PreprocessMountDisk(self)
    self.local_path = os.path.join(self.mount_path, self.embedded_path)

  def postprocess(self):
    google_cloud.PostprocessDetachDisk(self)
    mount_local.PreprocessUnmountDisk(self)


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
