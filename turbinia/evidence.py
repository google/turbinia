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
"""Turbinia Evidence objects."""

from __future__ import unicode_literals

import json
import os
import sys

from turbinia import config
from turbinia import TurbiniaException
from turbinia.processors import mount_local

# pylint: disable=keyword-arg-before-vararg

config.LoadConfig()
if config.TASK_MANAGER.lower() == 'psq':
  from turbinia.processors import google_cloud


def evidence_decode(evidence_dict):
  """Decode JSON into appropriate Evidence object.

  Args:
    evidence_dict: JSON serializable evidence object (i.e. a dict post JSON
                   decoding).

  Returns:
    An instantiated Evidence object (or a sub-class of it).

  Raises:
    TurbiniaException: If input is not a dict, does not have a type attribute,
                       or does not deserialize to an evidence object.
  """
  if not isinstance(evidence_dict, dict):
    raise TurbiniaException(
        'Evidence_dict is not a dictionary, type is {0:s}'.format(
            str(type(evidence_dict))))

  type_ = evidence_dict.get('type', None)
  if not type_:
    raise TurbiniaException(
        'No Type attribute for evidence object [{0:s}]'.format(
            str(evidence_dict)))

  try:
    evidence = getattr(sys.modules[__name__], type_)()
  except AttributeError:
    raise TurbiniaException(
        'No Evidence object of type {0:s} in evidence module'.format(type_))

  evidence.__dict__ = evidence_dict
  if evidence_dict['parent_evidence']:
    evidence.parent_evidence = evidence_decode(evidence_dict['parent_evidence'])
  return evidence


class Evidence(object):
  """Evidence object for processing.

  In most cases, these objects will just contain metadata about the actual
  evidence.

  Attributes:
    config (dict): Configuration options from the request to be used when
        processing this evidence.
    cloud_only: Set to True for evidence types that can only be processed in a
        cloud environment, e.g. GoogleCloudDisk.
    context_dependent: Whether this evidence is required to be built upon the
        context of a parent evidence.
    copyable: Whether this evidence can be copied.  This will be set to True for
        object types that we want to copy to/from storage (e.g. PlasoFile, but
        not RawDisk).
    name: Name of evidence.
    description: Description of evidence.
    saved_path (string): Path to secondary location evidence is saved for later
        retrieval (e.g. GCS).
    saved_path_type (string): The name of the output writer that saved evidence
        to the saved_path location.
    source: String indicating where evidence came from (including tool version
        that created it, if appropriate).
    local_path: A string of the local_path to the evidence.
    tags: dict of extra tags associated with this evidence.
    request_id: The id of the request this evidence came from, if any.
    parent_evidence: The Evidence object that was used to generate this one, and
        which pre/post process methods we need to re-execute to access data
        relevant to us.
  """

  # The list of attributes a given piece of Evidence requires to be set
  REQUIRED_ATTRIBUTES = []

  def __init__(
      self, name=None, description=None, source=None, local_path=None,
      tags=None, request_id=None):
    """Initialization for Evidence."""
    self.copyable = False
    self.config = {}
    self.context_dependent = False
    self.cloud_only = False
    self.description = description
    self.source = source
    self.local_path = local_path
    self.tags = tags if tags else {}
    self.request_id = request_id
    self.parent_evidence = None

    # List of jobs that have processed this evidence
    self.processed_by = []
    self.type = self.__class__.__name__
    self.name = name if name else self.type
    self.saved_path = None
    self.saved_path_type = None

  def __str__(self):
    return '{0:s}:{1:s}:{2!s}'.format(self.type, self.name, self.local_path)

  def __repr__(self):
    return self.__str__()

  def serialize(self):
    """Return JSON serializable object."""
    serialized_evidence = self.__dict__
    if self.parent_evidence:
      serialized_evidence['parent_evidence'] = self.parent_evidence.serialize()
    return serialized_evidence

  def to_json(self):
    """Convert object to JSON.

    Returns:
      A JSON serialized string of the current object.

    Raises:
      TurbiniaException: If serialization error occurs.
    """
    try:
      serialized = json.dumps(self.serialize())
    except TypeError as e:
      msg = 'JSON serialization of evidence object {0:s} failed: {1:s}'.format(
          self.type, str(e))
      raise TurbiniaException(msg)

    return serialized

  def _preprocess(self):
    """Preprocess this evidence prior to task running.

    This gets run in the context of the local task execution on the worker
    nodes prior to the task itself running.  This can be used to prepare the
    evidence to be processed (e.g. attach a cloud disk, mount a local disk etc).
    """
    pass

  def _postprocess(self):
    """Postprocess this evidence after the task runs.

    This gets run in the context of the local task execution on the worker
    nodes after the task has finished.  This can be used to clean-up after the
    evidence is processed (e.g. detach a cloud disk, etc,).
    """
    pass

  def preprocess(self):
    """Runs the possible parent's evidence preprocessing code, then ours.

    This is a wrapper function that will call the chain of pre-processors
    starting with the most distant ancestor.  After all of the ancestors have
    been processed, then we run our pre-processor.
    """
    if self.parent_evidence:
      self.parent_evidence.preprocess()
    self._preprocess()

  def postprocess(self):
    """Runs our postprocessing code, then our possible parent's evidence.

    This is is a wrapper function that will run our post-processor, and will
    then recurse down the chain of parent Evidence and run those post-processors
    in order.
    """
    self._postprocess()
    if self.parent_evidence:
      self.parent_evidence.postprocess()

  def validate(self):
    """Runs validation to verify evidence meets minimum requirements.

    This default implementation will just check that the attributes listed in
    REQUIRED_ATTRIBUTES are set, but other evidence types can override this
    method to implement their own more stringent checks as needed.  This is
    called by the worker, prior to the pre/post-processors running.

    Raises:
      TurbiniaException: If validation fails
    """
    for attribute in self.REQUIRED_ATTRIBUTES:
      attribute_value = getattr(self, attribute, None)
      if not attribute_value:
        message = (
            'Evidence validation failed: Required attribute {0:s} for class '
            '{1:s} is not set. Please check original request.'.format(
                attribute, self.name))
        raise TurbiniaException(message)


class Directory(Evidence):
  """Filesystem directory evidence."""
  pass


class ChromiumProfile(Evidence):
  """Chromium based browser profile evidence.

  Attributes:
    browser_type: The type of browser.
      Supported options are Chrome (default) and Brave.
    format: Output format (default is sqlite, other options are xlsx and jsonl)
  """

  REQUIRED_ATTRIBUTES = ['browser_type', 'output_format']

  def __init__(self, browser_type=None, output_format=None, *args, **kwargs):
    """Initialization for chromium profile evidence object."""
    super(ChromiumProfile, self).__init__(*args, **kwargs)
    self.browser_type = browser_type
    self.output_format = output_format
    self.copyable = True


class RawDisk(Evidence):
  """Evidence object for Disk based evidence.

  Attributes:
    loopdevice_path: Path to the losetup device for this disk.
    mount_path: The mount path for this disk (if any).
    mount_partition: The mount partition for this disk (if any).
    size:  The size of the disk in bytes.
  """

  def __init__(
      self, mount_path=None, mount_partition=None, size=None, *args, **kwargs):
    """Initialization for raw disk evidence object."""
    self.loopdevice_path = None
    self.mount_path = mount_path
    self.mount_partition = mount_partition
    self.size = size
    super(RawDisk, self).__init__(*args, **kwargs)

  def _preprocess(self):
    self.loopdevice_path = mount_local.PreprocessLosetup(self.local_path)

  def _postprocess(self):
    mount_local.PostprocessDeleteLosetup(self.loopdevice_path)
    self.loopdevice_path = None


class EncryptedDisk(RawDisk):
  """Encrypted disk file evidence.

  Attributes:
    encryption_type: The type of encryption used, e.g. FileVault or Bitlocker.
    encryption_key: A string of the encryption key used for this disk.
    unencrypted_path: A string to the unencrypted local path
  """

  def __init__(
      self, encryption_type=None, encryption_key=None, unencrypted_path=None,
      *args, **kwargs):
    """Initialization for Encrypted disk evidence objects."""
    # TODO(aarontp): Make this an enum, or limited list
    self.encryption_type = encryption_type
    self.encryption_key = encryption_key
    # self.local_path will be the encrypted path
    self.unencrypted_path = unencrypted_path
    super(EncryptedDisk, self).__init__(*args, **kwargs)


class BitlockerDisk(EncryptedDisk):
  """Bitlocker encrypted disk file evidence.

  Attributes:
    recovery_key: A string of the recovery key for this disk
    password: A string of the password used for this disk. If recovery key
        is used, this argument is ignored
    unencrypted_path: A string to the unencrypted local path
  """

  REQUIRED_ATTRIBUTES = ['recovery_key', 'password']

  def __init__(self, recovery_key=None, password=None, *args, **kwargs):
    """Initialization for Bitlocker disk evidence object"""
    self.recovery_key = recovery_key
    self.password = password
    super(BitlockerDisk, self).__init__(*args, **kwargs)
    self.encryption_type = self.__class__.__name__


class APFSEncryptedDisk(EncryptedDisk):
  """APFS encrypted disk file evidence.

  Attributes:
    recovery_key: A string of the recovery key for this disk
    password: A string of the password used for this disk. If recovery key
        is used, this argument is ignored
    unencrypted_path: A string to the unencrypted local path
  """

  REQUIRED_ATTRIBUTES = ['recovery_key', 'password']

  def __init__(self, recovery_key=None, password=None, *args, **kwargs):
    """Initialization for Bitlocker disk evidence object"""
    self.recovery_key = recovery_key
    self.password = password
    super(APFSEncryptedDisk, self).__init__(*args, **kwargs)
    self.encryption_type = self.__class__.__name__


class GoogleCloudDisk(RawDisk):
  """Evidence object for Google Cloud Disks.

  Attributes:
    project: The cloud project name this disk is associated with.
    zone: The geographic zone.
    disk_name: The cloud disk name.
  """

  REQUIRED_ATTRIBUTES = ['disk_name', 'project', 'zone']

  def __init__(self, project=None, zone=None, disk_name=None, *args, **kwargs):
    """Initialization for Google Cloud Disk."""
    self.project = project
    self.zone = zone
    self.disk_name = disk_name
    super(GoogleCloudDisk, self).__init__(*args, **kwargs)
    self.cloud_only = True

  def _preprocess(self):
    self.local_path = google_cloud.PreprocessAttachDisk(self.disk_name)

  def _postprocess(self):
    google_cloud.PostprocessDetachDisk(self.disk_name, self.local_path)
    self.local_path = None


class GoogleCloudDiskRawEmbedded(GoogleCloudDisk):
  """Evidence object for raw disks embedded in Persistent Disks.

  This is for a raw image file that is located in the filesystem of a mounted
  GCP Persistent Disk.  This can be useful if you want to process a raw disk
  image originating from outside cloud, and it is much more performant and
  reliable option than reading it directly from GCS FUSE.

  Attributes:
    embedded_path: The path of the raw disk image inside the Persistent Disk
  """

  REQUIRED_ATTRIBUTES = ['disk_name', 'project', 'zone', 'embedded_path']

  def __init__(self, embedded_path=None, *args, **kwargs):
    """Initialization for Google Cloud Disk."""
    self.embedded_path = embedded_path
    super(GoogleCloudDiskRawEmbedded, self).__init__(*args, **kwargs)

  def _preprocess(self):
    self.local_path = google_cloud.PreprocessAttachDisk(self.disk_name)
    self.loopdevice_path = mount_local.PreprocessLosetup(self.local_path)
    self.mount_path = mount_local.PreprocessMountDisk(
        self.loopdevice_path, self.mount_partition)
    self.local_path = os.path.join(self.mount_path, self.embedded_path)

  def _postprocess(self):
    google_cloud.PostprocessDetachDisk(self.disk_name, self.local_path)
    mount_local.PostprocessUnmountPath(self.mount_path)
    mount_local.PostprocessDeleteLosetup(self.loopdevice_path)


class PlasoFile(Evidence):
  """Plaso output file evidence.

  Attributes:
    plaso_version: The version of plaso that processed this file.
  """

  def __init__(self, plaso_version=None, *args, **kwargs):
    """Initialization for Plaso File evidence."""
    self.plaso_version = plaso_version
    super(PlasoFile, self).__init__(*args, **kwargs)
    self.copyable = True


class PlasoCsvFile(PlasoFile):
  """Psort output file evidence.  """

  def __init__(self, plaso_version=None, *args, **kwargs):
    """Initialization for Plaso File evidence."""
    self.plaso_version = plaso_version
    super(PlasoCsvFile, self).__init__(*args, **kwargs)


# TODO(aarontp): Find a way to integrate this into TurbiniaTaskResult instead.
class ReportText(Evidence):
  """Text data for general reporting."""

  def __init__(self, text_data=None, *args, **kwargs):
    self.text_data = text_data
    super(ReportText, self).__init__(*args, **kwargs)
    self.copyable = True


class TextFile(Evidence):
  """Text data."""

  def __init__(self, *args, **kwargs):
    super(TextFile, self).__init__(*args, **kwargs)
    self.copyable = True


class FilteredTextFile(TextFile):
  """Filtered text data."""
  pass


class ExportedFileArtifact(Evidence):
  """Exported file artifact."""

  REQUIRED_ATTRIBUTES = ['artifact_name']

  def __init__(self, artifact_name=None):
    """Initializes an exported file artifact."""
    super(ExportedFileArtifact, self).__init__()
    self.artifact_name = artifact_name
    self.copyable = True


class VolatilityReport(TextFile):
  """Volatility output file data."""
  pass


class RawMemory(Evidence):
  """Evidence object for Memory based evidence.

  Attributes:
    profile (string): Volatility profile used for the analysis
    module_list (list): Module used for the analysis
    """

  REQUIRED_ATTRIBUTES = ['module_list', 'profile']

  def __init__(self, module_list=None, profile=None, *args, **kwargs):
    """Initialization for raw memory evidence object."""
    super(RawMemory, self).__init__(*args, **kwargs)
    self.profile = profile
    self.module_list = module_list
