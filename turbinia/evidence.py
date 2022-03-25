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

from enum import IntEnum
import json
import logging
import os
import sys
import filelock

from turbinia import config
from turbinia import TurbiniaException
from turbinia.lib.docker_manager import GetDockerPath
from turbinia.processors import archive
from turbinia.processors import docker
from turbinia.processors import mount_local
from turbinia.processors import resource_manager

# pylint: disable=keyword-arg-before-vararg

config.LoadConfig()
if config.TASK_MANAGER.lower() == 'psq':
  from turbinia.processors import google_cloud

log = logging.getLogger('turbinia')


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

  type_ = evidence_dict.pop('type', None)
  if not type_:
    raise TurbiniaException(
        'No Type attribute for evidence object [{0:s}]'.format(
            str(evidence_dict)))

  try:
    evidence_class = getattr(sys.modules[__name__], type_)
    evidence = evidence_class.from_dict(evidence_dict)
  except AttributeError:
    raise TurbiniaException(
        'No Evidence object of type {0:s} in evidence module'.format(type_))

  if evidence_dict.get('parent_evidence'):
    evidence.parent_evidence = evidence_decode(evidence_dict['parent_evidence'])
  if evidence_dict.get('collection'):
    evidence.collection = [
        evidence_decode(e) for e in evidence_dict['collection']
    ]

  # We can just reinitialize instead of deserializing because the state should
  # be empty when just starting to process on a new machine.
  evidence.state = {}
  for state in EvidenceState:
    evidence.state[state] = False

  return evidence


class EvidenceState(IntEnum):
  """Runtime state of Evidence.

  Evidence objects will map each of these to a boolean indicating the current
  state for the given object.
  """
  MOUNTED = 1
  ATTACHED = 2
  DECOMPRESSED = 3
  CONTAINER_MOUNTED = 4


class Evidence:
  """Evidence object for processing.

  In most cases, these objects will just contain metadata about the actual
  evidence.

  Attributes:
    config (dict): Configuration options from the request to be used when
        processing this evidence.  Tasks should not read from this property
        directly, but should use `Task.task_config` to access any recipe or
        configuration variables.
    cloud_only (bool): Set to True for evidence types that can only be processed
        in a cloud environment, e.g. GoogleCloudDisk.
    context_dependent (bool): Whether this evidence is required to be built upon
        the context of a parent evidence.
    copyable (bool): Whether this evidence can be copied.  This will be set to
        True for object types that we want to copy to/from storage (e.g.
        PlasoFile, but not RawDisk).
    name (str): Name of evidence.
    description (str): Description of evidence.
    size (int): The evidence size in bytes where available (Used for metric
        tracking).
    saved_path (str): Path to secondary location evidence is saved for later
        retrieval (e.g. GCS).
    saved_path_type (str): The name of the output writer that saved evidence
        to the saved_path location.
    source (str): String indicating where evidence came from (including tool
        version that created it, if appropriate).
    local_path (str): Path to the processed data (can be a blockdevice or a
        mounted directory, etc).  This is the path that most Tasks should use to
        access evidence after it's been processed on the worker (i.e. when the
        Tasks `run()` method is called).  The last pre-processor to run should
        set this path.
    source_path (str): Path to the original un-processed source data for the
        Evidence.  This is the path that Evidence should be created and set up
        with initially.  Tasks should generally not use this path, but instead
        use the `local_path`.
    mount_path (str): Path to a mounted file system (if relevant).
    credentials (list): Decryption keys for encrypted evidence.
    tags (dict): Extra tags associated with this evidence.
    request_id (str): The id of the request this evidence came from, if any.
    has_child_evidence (bool): This property indicates the evidence object has
        child evidence.
    parent_evidence (Evidence): The Evidence object that was used to generate
        this one, and which pre/post process methods we need to re-execute to
        access data relevant to us.
    save_metadata (bool): Evidence with this property set will save a metadata
        file alongside the Evidence when saving to external storage.  The
        metadata file will contain all of the key=value pairs sent along with
        the processing request in the recipe.  The output is in JSON format
    state (dict): A map of each EvidenceState type to a boolean to indicate
        if that state is true.  This is used by the preprocessors to set the
        current state and Tasks can use this to determine if the Evidence is in
        the correct state for processing.
    resource_tracked (bool): Evidence with this property set requires tracking
        in a state file to allow for access amongst multiple workers.
    resource_id (str): The unique id used to track the state of a given Evidence
        type for stateful tracking.
  """

  # The list of attributes a given piece of Evidence requires to be set
  REQUIRED_ATTRIBUTES = []

  # The list of EvidenceState states that the Evidence supports in its
  # pre/post-processing (e.g. MOUNTED, ATTACHED, etc).  See `preprocessor()`
  # docstrings for more info.
  POSSIBLE_STATES = []

  def __init__(
      self, name=None, description=None, size=None, source=None,
      source_path=None, tags=None, request_id=None, copyable=False):
    """Initialization for Evidence."""
    self.copyable = copyable
    self.config = {}
    self.context_dependent = False
    self.cloud_only = False
    self.description = description
    self.size = size
    self.mount_path = None
    self.credentials = []
    self.source = source
    self.source_path = source_path
    self.tags = tags if tags else {}
    self.request_id = request_id
    self.has_child_evidence = False
    self.parent_evidence = None
    self.save_metadata = False
    self.resource_tracked = False
    self.resource_id = None

    self.local_path = source_path

    # List of jobs that have processed this evidence
    self.processed_by = []
    self.type = self.__class__.__name__
    self.name = name if name else self.type
    self.saved_path = None
    self.saved_path_type = None

    self.state = {}
    for state in EvidenceState:
      self.state[state] = False

    if self.copyable and not self.local_path:
      raise TurbiniaException(
          '{0:s} is a copyable evidence and needs a source_path'.format(
              self.type))

  def __str__(self):
    return '{0:s}:{1:s}:{2!s}'.format(self.type, self.name, self.source_path)

  def __repr__(self):
    return self.__str__()

  @classmethod
  def from_dict(cls, dictionary):
    """Instantiate an Evidence object from a dictionary of attributes.

    Args:
      dictionary(dict): the attributes to set for this object.
    Returns:
      Evidence: the instantiated evidence.
    """
    name = dictionary.pop('name', None)
    description = dictionary.pop('description', None)
    size = dictionary.pop('size', None)
    source = dictionary.pop('source', None)
    source_path = dictionary.pop('source_path', None)
    tags = dictionary.pop('tags', None)
    request_id = dictionary.pop('request_id', None)
    new_object = cls(
        name=name, description=description, size=size, source=source,
        source_path=source_path, tags=tags, request_id=request_id)
    new_object.__dict__.update(dictionary)
    return new_object

  def serialize(self):
    """Return JSON serializable object."""
    # Clear any partition path_specs before serializing
    if hasattr(self, 'path_spec'):
      self.path_spec = None
    serialized_evidence = self.__dict__.copy()
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

  def set_parent(self, parent_evidence):
    """Set the parent evidence of this evidence.

    Also adds this evidence as a child of the parent.

    Args:
      parent_evidence(Evidence): The parent evidence object.
    """
    parent_evidence.has_child_evidence = True
    self.parent_evidence = parent_evidence

  def _preprocess(self, _, required_states):
    """Preprocess this evidence prior to task running.

    See `preprocess()` docstrings for more info.

    Args:
      tmp_dir(str): The path to the temporary directory that the
          Task will write to.
      required_states(list[EvidenceState]): The list of evidence state
          requirements from the Task.
    """
    pass

  def _postprocess(self):
    """Postprocess this evidence after the task runs.

    This gets run in the context of the local task execution on the worker
    nodes after the task has finished.  This can be used to clean-up after the
    evidence is processed (e.g. detach a cloud disk, etc,).
    """
    pass

  def preprocess(self, task_id, tmp_dir=None, required_states=None):
    """Runs the possible parent's evidence preprocessing code, then ours.

    This is a wrapper function that will call the chain of pre-processors
    starting with the most distant ancestor.  After all of the ancestors have
    been processed, then we run our pre-processor.  These processors get run in
    the context of the local task execution on the worker nodes prior to the
    task itself running.  This can be used to prepare the evidence to be
    processed (e.g. attach a cloud disk, mount a local disk etc).

    Tasks export a list of the required_states they have for the state of the
    Evidence it can process in `TurbiniaTask.REQUIRED_STATES`[1].  Evidence also
    exports a list of the possible states it can have after pre/post-processing
    in `Evidence.POSSIBLE_STATES`.  The pre-processors should run selectively
    based on the these requirements that come from the Task, and the
    post-processors should run selectively based on the current state of the
    Evidence.

    If a Task requires a given state supported by the given Evidence class, but
    it is not met after the preprocessing of the Evidence is run, then the Task
    will abort early.  Note that for compound evidence types that have parent
    Evidence objects (e.g. where `context_dependent` is True), we only inspect
    the child Evidence type for its state as it is assumed that it would only be
    able to run the appropriate pre/post-processors when the parent Evidence
    processors have been successful.

    [1] Note that the evidence states required by the Task are only required if
    the Evidence also supports that state in `POSSSIBLE_STATES`.  This is so
    that the Tasks are flexible enough to support multiple types of Evidence.
    For example, `PlasoTask` allows both `CompressedDirectory` and
    `GoogleCloudDisk` as Evidence input, and has states `ATTACHED` and
    `DECOMPRESSED` listed in `PlasoTask.REQUIRED_STATES`.  Since `ATTACHED`
    state is supported by `GoogleCloudDisk`, and `DECOMPRESSED` is supported by
    `CompressedDirectory`, only those respective pre-processors will be run and
    the state is confirmed after the preprocessing is complete.

    Args:
      task_id(str): The id of a given Task.
      tmp_dir(str): The path to the temporary directory that the
                       Task will write to.
      required_states(list[EvidenceState]): The list of evidence state
          requirements from the Task.

    Raises:
      TurbiniaException: If the required evidence state cannot be met by the
          possible states of the Evidence or if the parent evidence object does
          not exist when it is required by the Evidence type..
    """
    self.local_path = self.source_path
    if not required_states:
      required_states = []

    if self.context_dependent:
      if not self.parent_evidence:
        raise TurbiniaException(
            'Evidence of type {0:s} needs parent_evidence to be set'.format(
                self.type))
      self.parent_evidence.preprocess(task_id, tmp_dir, required_states)
    try:
      log.debug('Starting pre-processor for evidence {0:s}'.format(self.name))
      if self.resource_tracked:
        # Track resource and task id in state file
        with filelock.FileLock(config.RESOURCE_FILE_LOCK):
          resource_manager.PreprocessResourceState(self.resource_id, task_id)
      self._preprocess(tmp_dir, required_states)
    except TurbiniaException as exception:
      log.error(
          'Error running preprocessor for {0:s}: {1!s}'.format(
              self.name, exception))

    log.debug(
        'Pre-processing evidence {0:s} is complete, and evidence is in state '
        '{1:s}'.format(self.name, self.format_state()))

  def postprocess(self, task_id):
    """Runs our postprocessing code, then our possible parent's evidence.

    This is is a wrapper function that will run our post-processor, and will
    then recurse down the chain of parent Evidence and run those post-processors
    in order.

    Args:
      task_id(str): The id of a given Task.
    """
    log.info('Starting post-processor for evidence {0:s}'.format(self.name))
    log.debug('Evidence state: {0:s}'.format(self.format_state()))

    is_detachable = True
    if self.resource_tracked:
      with filelock.FileLock(config.RESOURCE_FILE_LOCK):
        # Run postprocess to either remove task_id or resource_id.
        is_detachable = resource_manager.PostProcessResourceState(
            self.resource_id, task_id)
        if not is_detachable:
          # Prevent from running post process code if there are other tasks running.
          log.info(
              'Resource ID {0:s} still in use. Skipping detaching Evidence...'
              .format(self.resource_id))
        else:
          self._postprocess()
          # Set to False to prevent postprocess from running twice.
          is_detachable = False

    if is_detachable:
      self._postprocess()
    if self.parent_evidence:
      self.parent_evidence.postprocess(task_id)

  def format_state(self):
    """Returns a string representing the current state of evidence.

    Returns:
      str:  The state as a formatted string
    """
    output = []
    for state, value in self.state.items():
      output.append('{0:s}: {1!s}'.format(state.name, value))
    return '[{0:s}]'.format(', '.join(output))

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


class EvidenceCollection(Evidence):
  """A Collection of Evidence objects.

  Attributes:
    collection(list): The underlying Evidence objects
  """

  def __init__(self, collection=None, *args, **kwargs):
    """Initialization for Evidence Collection object."""
    super(EvidenceCollection, self).__init__(*args, **kwargs)
    self.collection = collection if collection else []

  def serialize(self):
    """Return JSON serializable object."""
    serialized_evidence = super(EvidenceCollection, self).serialize()
    serialized_evidence['collection'] = [e.serialize() for e in self.collection]
    return serialized_evidence

  def add_evidence(self, evidence):
    """Adds evidence to the collection.

    Args:
      evidence (Evidence): The evidence to add.
    """
    self.collection.append(evidence)


class Directory(Evidence):
  """Filesystem directory evidence."""
  pass


class CompressedDirectory(Evidence):
  """CompressedDirectory based evidence.

  Attributes:
    compressed_directory: The path to the compressed directory.
    uncompressed_directory: The path to the uncompressed directory.
  """

  POSSIBLE_STATES = [EvidenceState.DECOMPRESSED]

  def __init__(
      self, compressed_directory=None, uncompressed_directory=None, *args,
      **kwargs):
    """Initialization for CompressedDirectory evidence object."""
    super(CompressedDirectory, self).__init__(*args, **kwargs)
    self.compressed_directory = compressed_directory
    self.uncompressed_directory = uncompressed_directory
    self.copyable = True

  def _preprocess(self, tmp_dir, required_states):
    # Uncompress a given tar file and return the uncompressed path.
    if EvidenceState.DECOMPRESSED in required_states:
      self.uncompressed_directory = archive.UncompressTarFile(
          self.local_path, tmp_dir)
      self.local_path = self.uncompressed_directory
      self.state[EvidenceState.DECOMPRESSED] = True

  def compress(self):
    """ Compresses a file or directory.

    Creates a tar.gz from the uncompressed_directory attribute.
    """
    # Compress a given directory and return the compressed path.
    self.compressed_directory = archive.CompressDirectory(
        self.uncompressed_directory)
    self.source_path = self.compressed_directory
    self.state[EvidenceState.DECOMPRESSED] = False


class BulkExtractorOutput(CompressedDirectory):
  """Bulk Extractor based evidence."""
  pass


class PhotorecOutput(CompressedDirectory):
  """Photorec based evidence."""
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
    super(ChromiumProfile, self).__init__(copyable=True, *args, **kwargs)
    self.browser_type = browser_type
    self.output_format = output_format


class RawDisk(Evidence):
  """Evidence object for Disk based evidence.

  Attributes:
    device_path (str): Path to a relevant 'raw' data source (ie: a block
        device or a raw disk image).
    mount_partition: The mount partition for this disk (if any).
  """

  POSSIBLE_STATES = [EvidenceState.ATTACHED]

  def __init__(self, *args, **kwargs):
    """Initialization for raw disk evidence object."""
    self.device_path = None
    super(RawDisk, self).__init__(*args, **kwargs)

  def _preprocess(self, _, required_states):
    if self.size is None:
      self.size = mount_local.GetDiskSize(self.source_path)
    if EvidenceState.ATTACHED in required_states or self.has_child_evidence:
      self.device_path = mount_local.PreprocessLosetup(self.source_path)
      self.state[EvidenceState.ATTACHED] = True
      self.local_path = self.device_path

  def _postprocess(self):
    if self.state[EvidenceState.ATTACHED]:
      mount_local.PostprocessDeleteLosetup(self.device_path)
      self.state[EvidenceState.ATTACHED] = False


class DiskPartition(RawDisk):
  """Evidence object for a partition within Disk based evidence.

  More information on dfVFS types:
  https://dfvfs.readthedocs.io/en/latest/sources/Path-specifications.html

  Attributes:
    partition_location (str): dfVFS partition location (The location of the
        volume within the volume system, similar to a volume identifier).
    partition_offset (int): Offset of the partition in bytes.
    partition_size (int): Size of the partition in bytes.
    path_spec (dfvfs.PathSpec): Partition path spec.
  """

  POSSIBLE_STATES = [EvidenceState.ATTACHED, EvidenceState.MOUNTED]

  def __init__(
      self, partition_location=None, partition_offset=None, partition_size=None,
      lv_uuid=None, path_spec=None, *args, **kwargs):
    """Initialization for raw volume evidence object."""

    self.partition_location = partition_location
    self.partition_offset = partition_offset
    self.partition_size = partition_size
    self.lv_uuid = lv_uuid
    self.path_spec = path_spec
    super(DiskPartition, self).__init__(*args, **kwargs)

    # This Evidence needs to have a parent
    self.context_dependent = True

  def _preprocess(self, _, required_states):
    # Late loading the partition processor to avoid loading dfVFS unnecessarily.
    from turbinia.processors import partitions

    # We need to enumerate partitions in preprocessing so the path_specs match
    # the parent evidence location for each task.
    try:
      path_specs = partitions.Enumerate(self.parent_evidence)
    except TurbiniaException as e:
      log.error(e)

    path_spec = partitions.GetPathSpecByLocation(
        path_specs, self.partition_location)
    if path_spec:
      self.path_spec = path_spec
    else:
      raise TurbiniaException(
          'Could not find path_spec for location {0:s}'.format(
              self.partition_location))

    # In attaching a partition, we create a new loopback device using the
    # partition offset and size.
    if EvidenceState.ATTACHED in required_states or self.has_child_evidence:
      # Check for encryption
      encryption_type = partitions.GetPartitionEncryptionType(path_spec)
      if encryption_type == 'BDE':
        self.device_path = mount_local.PreprocessBitLocker(
            self.parent_evidence.device_path,
            partition_offset=self.partition_offset,
            credentials=self.parent_evidence.credentials)
        if not self.device_path:
          log.error('Could not decrypt partition.')
      else:
        self.device_path = mount_local.PreprocessLosetup(
            self.parent_evidence.device_path,
            partition_offset=self.partition_offset,
            partition_size=self.partition_size, lv_uuid=self.lv_uuid)
      if self.device_path:
        self.state[EvidenceState.ATTACHED] = True
        self.local_path = self.device_path

    if EvidenceState.MOUNTED in required_states or self.has_child_evidence:
      self.mount_path = mount_local.PreprocessMountPartition(
          self.device_path, self.path_spec.type_indicator)
      if self.mount_path:
        self.local_path = self.mount_path
        self.state[EvidenceState.MOUNTED] = True

  def _postprocess(self):
    if self.state[EvidenceState.MOUNTED]:
      mount_local.PostprocessUnmountPath(self.mount_path)
      self.state[EvidenceState.MOUNTED] = False
    if self.state[EvidenceState.ATTACHED]:
      # Late loading the partition processor to avoid loading dfVFS unnecessarily.
      from turbinia.processors import partitions

      # Check for encryption
      encryption_type = partitions.GetPartitionEncryptionType(self.path_spec)
      if encryption_type == 'BDE':
        # bdemount creates a virtual device named bde1 in the mount path. This
        # needs to be unmounted rather than detached.
        mount_local.PostprocessUnmountPath(self.device_path.replace('bde1', ''))
        self.state[EvidenceState.ATTACHED] = False
      else:
        mount_local.PostprocessDeleteLosetup(self.device_path, self.lv_uuid)
        self.state[EvidenceState.ATTACHED] = False


class GoogleCloudDisk(RawDisk):
  """Evidence object for a Google Cloud Disk.

  Attributes:
    project: The cloud project name this disk is associated with.
    zone: The geographic zone.
    disk_name: The cloud disk name.
  """

  REQUIRED_ATTRIBUTES = ['disk_name', 'project', 'resource_id', 'zone']
  POSSIBLE_STATES = [EvidenceState.ATTACHED, EvidenceState.MOUNTED]

  def __init__(
      self, project=None, zone=None, disk_name=None, mount_partition=1, *args,
      **kwargs):
    """Initialization for Google Cloud Disk."""
    self.project = project
    self.zone = zone
    self.disk_name = disk_name
    self.mount_partition = mount_partition
    self.partition_paths = None
    super(GoogleCloudDisk, self).__init__(*args, **kwargs)
    self.cloud_only = True
    self.resource_tracked = True
    self.resource_id = self.disk_name

  def _preprocess(self, _, required_states):
    # The GoogleCloudDisk should never need to be mounted unless it has child
    # evidence (GoogleCloudDiskRawEmbedded). In all other cases, the
    # DiskPartition evidence will be used. In this case we're breaking the
    # evidence layer isolation and having the child evidence manage the
    # mounting and unmounting.

    # Explicitly lock this method to prevent race condition with two workers
    # attempting to attach disk at same time, given delay with attaching in GCP.
    with filelock.FileLock(config.RESOURCE_FILE_LOCK):
      if EvidenceState.ATTACHED in required_states:
        self.device_path, partition_paths = google_cloud.PreprocessAttachDisk(
            self.disk_name)
        self.partition_paths = partition_paths
        self.local_path = self.device_path
        self.state[EvidenceState.ATTACHED] = True

  def _postprocess(self):
    if self.state[EvidenceState.ATTACHED]:
      google_cloud.PostprocessDetachDisk(self.disk_name, self.device_path)
      self.state[EvidenceState.ATTACHED] = False


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
  POSSIBLE_STATES = [EvidenceState.ATTACHED]

  def __init__(self, embedded_path=None, *args, **kwargs):
    """Initialization for Google Cloud Disk containing a raw disk image."""
    self.embedded_path = embedded_path
    super(GoogleCloudDiskRawEmbedded, self).__init__(*args, **kwargs)

    # This Evidence needs to have a GoogleCloudDisk as a parent
    self.context_dependent = True

  def _preprocess(self, _, required_states):
    # Need to mount parent disk
    if not self.parent_evidence.partition_paths:
      self.parent_evidence.mount_path = mount_local.PreprocessMountPartition(
          self.parent_evidence.device_path)
    else:
      partition_paths = self.parent_evidence.partition_paths
      self.parent_evidence.mount_path = mount_local.PreprocessMountDisk(
          partition_paths, self.parent_evidence.mount_partition)
    self.parent_evidence.local_path = self.parent_evidence.mount_path
    self.parent_evidence.state[EvidenceState.MOUNTED] = True

    if EvidenceState.ATTACHED in required_states or self.has_child_evidence:
      rawdisk_path = os.path.join(
          self.parent_evidence.mount_path, self.embedded_path)
      if not os.path.exists(rawdisk_path):
        raise TurbiniaException(
            'Unable to find raw disk image {0:s} in GoogleCloudDisk'.format(
                rawdisk_path))
      self.device_path = mount_local.PreprocessLosetup(rawdisk_path)
      self.state[EvidenceState.ATTACHED] = True
      self.local_path = self.device_path

  def _postprocess(self):
    if self.state[EvidenceState.ATTACHED]:
      mount_local.PostprocessDeleteLosetup(self.device_path)
      self.state[EvidenceState.ATTACHED] = False

    # Need to unmount parent disk
    if self.parent_evidence.state[EvidenceState.MOUNTED]:
      mount_local.PostprocessUnmountPath(self.parent_evidence.mount_path)
      self.parent_evidence.state[EvidenceState.MOUNTED] = False


class PlasoFile(Evidence):
  """Plaso output file evidence.

  Attributes:
    plaso_version: The version of plaso that processed this file.
  """

  def __init__(self, plaso_version=None, *args, **kwargs):
    """Initialization for Plaso File evidence."""
    self.plaso_version = plaso_version
    super(PlasoFile, self).__init__(copyable=True, *args, **kwargs)
    self.save_metadata = True


class PlasoCsvFile(Evidence):
  """Psort output file evidence.  """

  def __init__(self, plaso_version=None, *args, **kwargs):
    """Initialization for Plaso File evidence."""
    self.plaso_version = plaso_version
    super(PlasoCsvFile, self).__init__(copyable=True, *args, **kwargs)
    self.save_metadata = False


# TODO(aarontp): Find a way to integrate this into TurbiniaTaskResult instead.
class ReportText(Evidence):
  """Text data for general reporting."""

  def __init__(self, text_data=None, *args, **kwargs):
    self.text_data = text_data
    super(ReportText, self).__init__(copyable=True, *args, **kwargs)


class FinalReport(ReportText):
  """Report format for the final complete Turbinia request report."""

  def __init__(self, *args, **kwargs):
    super(FinalReport, self).__init__(*args, **kwargs)
    self.save_metadata = True


class TextFile(Evidence):
  """Text data."""

  def __init__(self, *args, **kwargs):
    super(TextFile, self).__init__(copyable=True, *args, **kwargs)


class FilteredTextFile(TextFile):
  """Filtered text data."""
  pass


class BodyFile(Evidence):
  """Bodyfile data."""

  def __init__(self, *args, **kwargs):
    self.number_of_entries = None
    super(BodyFile, self).__init__(copyable=True, *args, **kwargs)


class ExportedFileArtifact(Evidence):
  """Exported file artifact."""

  REQUIRED_ATTRIBUTES = ['artifact_name']

  def __init__(self, artifact_name=None, *args, **kwargs):
    """Initializes an exported file artifact."""
    super(ExportedFileArtifact, self).__init__(copyable=True, *args, **kwargs)
    self.artifact_name = artifact_name


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


class BinaryExtraction(CompressedDirectory):
  """Binaries extracted from evidence."""
  pass


class DockerContainer(Evidence):
  """Evidence object for a DockerContainer filesystem.

  Attributes:
    container_id(str): The ID of the container to mount.
    _container_fs_path(str): Full path to where the container filesystem will
      be mounted.
    _docker_root_directory(str): Full path to the docker root directory.
  """

  POSSIBLE_STATES = [EvidenceState.CONTAINER_MOUNTED]

  def __init__(self, container_id=None, *args, **kwargs):
    """Initialization for Docker Container."""
    super(DockerContainer, self).__init__(*args, **kwargs)
    self.container_id = container_id
    self._container_fs_path = None
    self._docker_root_directory = None

    self.context_dependent = True

  def _preprocess(self, _, required_states):
    if EvidenceState.CONTAINER_MOUNTED in required_states:
      self._docker_root_directory = GetDockerPath(
          self.parent_evidence.mount_path)
      # Mounting the container's filesystem
      self._container_fs_path = docker.PreprocessMountDockerFS(
          self._docker_root_directory, self.container_id)
      self.mount_path = self._container_fs_path
      self.local_path = self.mount_path
      self.state[EvidenceState.CONTAINER_MOUNTED] = True

  def _postprocess(self):
    if self.state[EvidenceState.CONTAINER_MOUNTED]:
      # Unmount the container's filesystem
      mount_local.PostprocessUnmountPath(self._container_fs_path)
      self.state[EvidenceState.CONTAINER_MOUNTED] = False
