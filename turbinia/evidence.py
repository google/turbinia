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

from enum import IntEnum
from collections import defaultdict
from typing import Any

import filelock
import inspect
import json
import logging
import os
import subprocess
import sys
import uuid

from turbinia import config
from turbinia import TurbiniaException
from turbinia.processors import archive
from turbinia.processors import containerd
from turbinia.processors import docker
from turbinia.processors import mount_local
from turbinia.processors import resource_manager
from turbinia.config import DATETIME_FORMAT
from datetime import datetime

config.LoadConfig()
if config.CLOUD_PROVIDER.lower() == 'gcp':
  from turbinia.processors import google_cloud

log = logging.getLogger(__name__)


def evidence_class_names(all_classes=False):
  """Returns a list of class names for the evidence module.

  Args:
    all_classes (bool): Flag to determine whether to include all classes
        in the module.

  Returns:
    class_names (list[str]): A list of class names within the Evidence module,
        minus the ignored class names.
  """
  predicate = lambda member: inspect.isclass(member) and not inspect.isbuiltin(
      member)
  class_names = inspect.getmembers(sys.modules[__name__], predicate)
  if not all_classes:
    # TODO: Non-evidence types should be moved out of the evidence module,
    # so that we no longer have to ignore certain classes here. Especially
    # 'output' and 'report' types.
    # Ignore classes that are not real Evidence types and the base class.
    ignored_classes = (
        'BinaryExtraction', 'BulkExtractorOutput', 'Evidence', 'EvidenceState',
        'EvidenceCollection', 'ExportedFileArtifact', 'ExportedFileArtifactLLM',
        'FilteredTextFile', 'FinalReport', 'IntEnum', 'PlasoCsvFile',
        'PhotorecOutput', 'ReportText', 'TextFile', 'VolatilityReport',
        'TurbiniaException')
    class_names = filter(
        lambda class_tuple: class_tuple[0] not in ignored_classes, class_names)
  return list(class_names)


def map_evidence_attributes():
  """Creates a dictionary that maps evidence types to their
       constructor attributes.

  Returns:
    object_attribute_mapping (defaultdict): A mapping of evidence types
        and their constructor attributes.
  """
  object_attribute_mapping = defaultdict(list)
  for class_name, class_type in evidence_class_names():
    try:
      attributes_signature = inspect.signature(class_type)
      attributes = attributes_signature.parameters.keys()
      for attribute in attributes:
        if not object_attribute_mapping[class_name]:
          object_attribute_mapping[class_name] = defaultdict(dict)
        # Ignore 'args' and 'kwargs' attributes.
        if attribute not in ('args', 'kwargs'):
          object_attribute_mapping[class_name][attribute] = {
              'required': bool(attribute in class_type.REQUIRED_ATTRIBUTES),
              'type': 'str'
          }
      # Add optional attributes.
      for optional_attribute in Evidence.OPTIONAL_ATTRIBUTES:
        object_attribute_mapping[class_name][optional_attribute] = {
            'required': False,
            'type': 'str'
        }
    except ValueError as exception:
      log.debug(exception)
  return object_attribute_mapping


def evidence_decode(evidence_dict, strict=False):
  """Decode JSON into appropriate Evidence object.

  Args:
    evidence_dict: JSON serializable evidence object (i.e. a dict post JSON
                   decoding).
    strict: Flag to indicate whether strict attribute validation will occur.
        Defaults to False.

  Returns:
    An instantiated Evidence object (or a sub-class of it) or None.

  Raises:
    TurbiniaException: If input is not a dict, does not have a type attribute,
                       or does not deserialize to an evidence object.
  """
  if not isinstance(evidence_dict, dict):
    raise TurbiniaException(
        f'Evidence_dict is not a dictionary, type is {str(type(evidence_dict)):s}'
    )
  type_ = evidence_dict.pop('type', None)
  name_ = evidence_dict.pop('_name', None)
  if not type_:
    raise TurbiniaException(
        f'No Type attribute for evidence object [{str(evidence_dict):s}]')
  evidence = None
  try:
    evidence_class = getattr(sys.modules[__name__], type_)
    evidence = evidence_class(name=name_, type=type_, **evidence_dict)
    evidence_object = evidence_class(source_path='dummy_object')
    if strict and evidence_object:
      for attribute_key in evidence_dict.keys():
        if not attribute_key in evidence_object.__dict__:
          message = f'Invalid attribute {attribute_key!s} for evidence type {type_:s}'
          log.error(message)
          raise TurbiniaException(message)
    if evidence:
      if evidence_dict.get('parent_evidence'):
        evidence.parent_evidence = evidence_decode(
            evidence_dict['parent_evidence'])
      if evidence_dict.get('collection'):
        evidence.collection = [
            evidence_decode(e) for e in evidence_dict['collection']
        ]
      # We can just reinitialize instead of deserializing because the
      # state should be empty when just starting to process on a new machine.
      evidence.state = {}
      for state in EvidenceState:
        evidence.state[state] = False
  except AttributeError:
    message = f'No Evidence object of type {type_!s} in evidence module'
    log.error(message)
    raise TurbiniaException(message) from AttributeError

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
    creation_time (datetime): The time the evidence was created.
    name (str): Name of evidence.
    description (str): Description of evidence.
    hash (str): The hash value of the file/device associated with this evidence.
    size (int): The evidence size in bytes where available (Used for metric
        tracking).
    saved_path (str): Path to secondary location evidence is saved for later
        retrieval (e.g. GCS).
    saved_path_type (str): The name of the output writer that saved evidence
        to the saved_path location.
    source (str): String indicating where evidence came from (including tool
        version that created it, if appropriate).
    local_path (str): Generic path to the evidence data after pre-processing
        has been run.  This is the path that most Tasks and any code that runs
        after the pre-processors should use to access evidence. Depending on
        the pre-processors and `REQUIRED_STATE` for the Task being run, this
        could point to a blockdevice or a mounted directory. The last
        pre-processor to run should always set this path. For example if the
        Evidence is a `RawDisk`, the `source_path` will be a path to the image
        file, then the pre-processors will (optionally, depending on the Task
        requirements) create a loop device and mount it which will set the
        `device_path` and `mount_path` respectively. After that, the
        `local_path` should point to whatever path the last pre-processor has
        created, in this case the mount_path.
    source_path (str): Path to the original un-processed source data for the
        Evidence.  This is the path that Evidence should be created and set up
        with initially and used any time prior to when the pre-processors run.
        Tasks should generally not use `source_path`, but instead use the
        `local_path` (or other more specific paths like `device_path` or
        `mount_path` depending on the Task requirements).
    mount_path (str): Path to a mounted file system (if relevant).
    credentials (list): Decryption keys for encrypted evidence.
    tags (dict): Extra tags associated with this evidence.
    tasks (list): List of tasks that have processed this evidence.
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

  Note:
    Evidence objects will be serialized by the state manager through the
    `to_json()` method. The state manager will store JSON serializable
    evidence objects in the datastore (e.g Redis) as TurbiniaEvidence keys
    by calling the `write_evidence()` method. The `TurbiniaEvidence` keys
    will contain all the attributes except the `config` attribute because
    it can be quite large and is currently not necessary to store it. If
    the evidence object contains the `hash` attribute, the state manager
    will update a `TurbiniaEvidenceHashes` key with the corresponding hash
    value and evidence id.
  """

  # The list of attributes a given piece of Evidence requires to be set
  REQUIRED_ATTRIBUTES = ['id']

  # An optional set of attributes that are generally used to describe
  # a given piece of Evidence.
  OPTIONAL_ATTRIBUTES = {'name', 'source', 'description', 'tags'}

  # The list of EvidenceState states that the Evidence supports in its
  # pre/post-processing (e.g. MOUNTED, ATTACHED, etc).  See `preprocessor()`
  # docstrings for more info.
  POSSIBLE_STATES = []

  def __init__(self, *args, **kwargs):
    """Initialization for Evidence."""
    self.id = kwargs.get('id', uuid.uuid4().hex)
    self.cloud_only = kwargs.get('cloud_only', False)
    self.config = kwargs.get('config', {})
    self.context_dependent = kwargs.get('context_dependent', False)
    self.copyable = kwargs.get('copyable', False)
    self.creation_time = kwargs.get(
        'creation_time',
        datetime.now().strftime(DATETIME_FORMAT))
    self.credentials = kwargs.get('credentials', [])
    self.description = kwargs.get('description', None)
    self.has_child_evidence = kwargs.get('has_child_evidence', False)
    self.hash = kwargs.get('hash', None)
    self.mount_path = kwargs.get('mount_path', None)
    self._name = kwargs.get('name')
    self.parent_evidence = kwargs.get('parent_evidence', None)
    self.request_id = kwargs.get('request_id', None)
    self.resource_id = kwargs.get('resource_id', None)
    self.resource_tracked = kwargs.get('resource_tracked', False)
    self.save_metadata = kwargs.get('save_metadata', False)
    self.saved_path = kwargs.get('saved_path', None)
    self.saved_path_type = kwargs.get('saved_path_type', None)
    self.size = kwargs.get('size', None)
    self.source = kwargs.get('source', None)
    self.source_path = kwargs.get('source_path', None)
    self.tags = kwargs.get('tags', {})
    self.tasks = kwargs.get('tasks', [])
    self.type = self.__class__.__name__
    self.local_path = self.source_path

    if 'state' in kwargs:
      self.state = kwargs.get('state')
    else:
      self.state = {}
      for state in EvidenceState:
        self.state[state] = False

    if self.copyable and not self.local_path:
      raise TurbiniaException(
          'Unable to initialize object, {0:s} is a copyable '
          'evidence and needs a source_path'.format(self.type))

    # TODO: Validating for required attributes breaks some units tests.
    # Github issue: https://github.com/google/turbinia/issues/1136
    # self.validate()

  def __str__(self):
    return f'{self.type:s}:{self.name:s}:{self.source_path!s}'

  def __repr__(self):
    return self.__str__()

  def __setattr__(self, attribute_name: str, attribute_value: Any):
    """Sets the value of the attribute and updates last_update.

    Args:
      attribute_name (str): name of the attribute to be set.
      attribute_value (Any): value to be set.
    """
    if attribute_name == 'name':
      attribute_name = '_name'
    self.__dict__[attribute_name] = attribute_value
    if attribute_name != 'last_update':
      self.last_update = datetime.now().strftime(DATETIME_FORMAT)

  @property
  def name(self):
    """Returns evidence object name."""
    if self._name:
      return self._name
    else:
      return self.source_path if self.source_path else self.type

  @name.deleter
  def name(self):
    del self._name

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

  def serialize_attribute(self, name: str) -> str:
    """Returns JSON serialized attribute.

    Args:
      name(str): the name of the attribute that will be serialized.
    Returns:
      A string containing the serialized attribute.
    """
    if hasattr(self, name):
      try:
        return json.dumps(getattr(self, name))
      except (TypeError, OverflowError):
        log.error(f'Attribute {name} in evidence {self.id} is not serializable')
    else:
      log.error(f'Evidence {self.id} has no attribute {name}')

  def serialize(self, json_values: bool = False):
    """Returns a JSON serialized object. The function will return A string
    containing the serialized evidence_dict or a dict of serialized attributes
    if json_values is true.

    Args:
      json_values(bool): Returns only values of the dictionary as json strings
        instead of the entire dictionary.

    Returns:
      JSON serialized object.
    """
    # Clear any partition path_specs before serializing
    if hasattr(self, 'path_spec'):
      self.path_spec = None
    serialized_evidence = {}
    if json_values:
      for attribute_name in self.__dict__:
        if serialized_attribute := self.serialize_attribute(attribute_name):
          serialized_evidence[attribute_name] = serialized_attribute
    else:
      serialized_evidence = self.__dict__.copy()
      if self.parent_evidence:
        serialized_evidence['parent_evidence'] = self.parent_evidence.serialize(
        )
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
    except TypeError as exception:
      msg = 'JSON serialization of evidence object {0:s} failed: {1:s}'.format(
          self.type, str(exception))
      raise TurbiniaException(msg) from exception

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
    For example, `PlasoParserTask` allows both `CompressedDirectory` and
    `GoogleCloudDisk` as Evidence input, and has states `ATTACHED` and
    `DECOMPRESSED` listed in `PlasoParserTask.REQUIRED_STATES`.  Since `ATTACHED`
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
          not exist when it is required by the Evidence type.
    """
    self.local_path = self.source_path
    if not required_states:
      required_states = []

    if not self.size and self.source_path:
      self.size = mount_local.GetDiskSize(self.source_path)

    if self.context_dependent:
      if not self.parent_evidence:
        raise TurbiniaException(
            f'Evidence of type {self.type:s} needs parent_evidence to be set')
      log.debug(
          'Evidence is context dependent. Running preprocess for parent_evidence '
          '{0:s}'.format(self.parent_evidence.name))
      self.parent_evidence.preprocess(task_id, tmp_dir, required_states)
    try:
      log.info(f'Starting preprocessor for evidence {self.name:s}')
      if self.resource_tracked:
        # Track resource and task id in state file
        log.debug(
            'Evidence {0:s} is resource tracked. Acquiring filelock for'
            'preprocessing'.format(self.name))
        with filelock.FileLock(config.RESOURCE_FILE_LOCK):
          resource_manager.PreprocessResourceState(self.resource_id, task_id)
          self._preprocess(tmp_dir, required_states)
      else:
        log.debug(
            f'Evidence {self.name:s} is not resource tracked. Running preprocess.'
        )
        self._preprocess(tmp_dir, required_states)
    except TurbiniaException as exception:
      log.error(f'Error running preprocessor for {self.name:s}: {exception!s}')

    log.info(
        'Preprocessing evidence {0:s} is complete, and evidence is in state '
        '{1:s}'.format(self.name, self.format_state()))

  def postprocess(self, task_id):
    """Runs our postprocessing code, then our possible parent's evidence.

    This is is a wrapper function that will run our post-processor, and will
    then recurse down the chain of parent Evidence and run those post-processors
    in order.

    Args:
      task_id(str): The id of a given Task.
    """
    log.info(f'Starting postprocessor for evidence {self.name:s}')
    log.debug(f'Evidence state: {self.format_state():s}')

    if self.resource_tracked:
      log.debug(
          'Evidence: {0:s} is resource tracked. Acquiring filelock for '
          'postprocessing.'.format(self.name))
      with filelock.FileLock(config.RESOURCE_FILE_LOCK):
        # Run postprocess to either remove task_id or resource_id.
        is_detachable = resource_manager.PostProcessResourceState(
            self.resource_id, task_id)
        if not is_detachable:
          # Skip post process if there are other tasks still processing the
          # Evidence.
          log.info(
              'Resource ID {0:s} still in use. Skipping detaching Evidence.'
              .format(self.resource_id))
        else:
          self._postprocess()
          if self.parent_evidence:
            log.debug(
                'Evidence {0:s} has parent_evidence. Running postprocess '
                'for parent evidence {1:s}.'.format(
                    self.name, self.parent_evidence.name))
            self.parent_evidence.postprocess(task_id)
    else:
      log.debug(
          f'Evidence {self.name:s} is not resource tracked. Running postprocess.'
      )
      self._postprocess()
      if self.parent_evidence:
        log.debug(
            'Evidence {0:s} has parent_evidence. Running postprocess '
            'for parent evidence {1:s}.'.format(
                self.name, self.parent_evidence.name))
        self.parent_evidence.postprocess(task_id)

  def format_state(self):
    """Returns a string representing the current state of evidence.

    Returns:
      str:  The state as a formatted string
    """
    output = []
    for state, value in self.state.items():
      output.append(f'{state.name:s}: {value!s}')
    return f"[{', '.join(output):s}]"

  def _validate(self):
    """Runs additional logic to validate evidence requirements.

    Evidence subclasses can override this method to perform custom
    validation of evidence objects.
    """
    pass

  def validate_attributes(self):
    """Runs validation to verify evidence meets minimum requirements.

    This default implementation will just check that the attributes listed in
    REQUIRED_ATTRIBUTES are set, but other evidence types can override this
    method to implement their own more stringent checks as needed.  This is
    called by the worker, prior to the pre/post-processors running.

    Raises:
      TurbiniaException: If validation fails, or when encountering an error.
    """
    for attribute in self.REQUIRED_ATTRIBUTES:
      attribute_value = getattr(self, attribute, None)
      if not attribute_value:
        message = (
            f'Evidence validation failed: Required attribute {attribute} for '
            f'evidence {getattr(self, "id", "(ID not set)")} of class '
            f'{getattr(self, "type", "(type not set)")} is not set. Please '
            f'check original request.')
        raise TurbiniaException(message)

  def validate(self):
    """Runs validation to verify evidence meets minimum requirements, including
    PlasoFile evidence.

    This default implementation will just check that the attributes listed in
    REQUIRED_ATTRIBUTES are set, but other evidence types can override this
    method to implement their own more stringent checks as needed.  This is
    called by the worker, prior to the pre/post-processors running.

    Raises:
      TurbiniaException: If validation fails, or when encountering an error.
    """
    self.validate_attributes()
    self._validate()


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
  """Filesystem directory evidence.

  Attributes:
    source_path: The path to the source directory used as evidence.
  """
  REQUIRED_ATTRIBUTES = ['source_path']

  def __init__(self, source_path=None, *args, **kwargs):
    super(Directory, self).__init__(source_path=source_path, *args, **kwargs)
    self.source_path = source_path


class CompressedDirectory(Evidence):
  """CompressedDirectory based evidence.

  Attributes:
    compressed_directory: The path to the compressed directory.
    uncompressed_directory: The path to the uncompressed directory.
  """
  REQUIRED_ATTRIBUTES = ['source_path']
  POSSIBLE_STATES = [EvidenceState.DECOMPRESSED]

  def __init__(self, source_path=None, *args, **kwargs):
    """Initialization for CompressedDirectory evidence object."""
    super(CompressedDirectory, self).__init__(
        source_path=source_path, *args, **kwargs)
    self.compressed_directory = None
    self.uncompressed_directory = None
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
    super(ChromiumProfile, self).__init__(*args, **kwargs)
    self.browser_type = browser_type
    self.output_format = output_format
    self.copyable = True


class RawDisk(Evidence):
  """Evidence object for Disk based evidence.

  Attributes:
    source_path (str): Path to a relevant 'raw' data source (ie: a block
        device or a raw disk image).
    mount_partition: The mount partition for this disk (if any).
  """
  REQUIRED_ATTRIBUTES = ['source_path']
  POSSIBLE_STATES = [EvidenceState.ATTACHED]

  def __init__(self, source_path=None, *args, **kwargs):
    """Initialization for raw disk evidence object."""
    super(RawDisk, self).__init__(source_path=source_path, *args, **kwargs)
    self.device_path = None

  def _preprocess(self, _, required_states):
    if EvidenceState.ATTACHED in required_states or self.has_child_evidence:
      self.device_path = mount_local.PreprocessLosetup(self.source_path)
      self.state[EvidenceState.ATTACHED] = True
      self.local_path = self.device_path

  def _postprocess(self):
    if self.state[EvidenceState.ATTACHED]:
      mount_local.PostprocessDeleteLosetup(self.device_path)
      self.state[EvidenceState.ATTACHED] = False


class DiskPartition(Evidence):
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
      lv_uuid=None, path_spec=None, important=True, *args, **kwargs):
    """Initialization for raw volume evidence object."""
    super(DiskPartition, self).__init__(*args, **kwargs)
    self.partition_location = partition_location
    if partition_offset:
      try:
        self.partition_offset = int(partition_offset)
      except ValueError as exception:
        log.error(
            f'Unable to cast partition_offset attribute to integer. {exception!s}'
        )
    else:
      self.partition_offset = None
    if partition_size:
      try:
        self.partition_size = int(partition_size)
      except ValueError as exception:
        log.error(
            f'Unable to cast partition_size attribute to integer. {exception!s}'
        )
    else:
      self.partition_size = None
    self.lv_uuid = lv_uuid
    self.path_spec = path_spec
    self.important = important

    # This Evidence needs to have a parent
    self.context_dependent = True

  @property
  def name(self):
    if self._name:
      return self._name
    else:
      if self.parent_evidence:
        return ':'.join((self.parent_evidence.name, self.partition_location))
      else:
        return ':'.join((self.type, self.partition_location))

  def _preprocess(self, _, required_states):
    # Late loading the partition processor to avoid loading dfVFS unnecessarily.
    from turbinia.processors import partitions

    # We need to enumerate partitions in preprocessing so the path_specs match
    # the parent evidence location for each task.
    path_specs = None
    try:
      # We should only get one path_spec here since we're specifying the location.
      path_specs = partitions.Enumerate(
          self.parent_evidence, self.partition_location)
    except TurbiniaException as exception:
      log.error(exception)

    if not path_specs:
      raise TurbiniaException(
          f'Could not find path_spec for location {self.partition_location:s}')
    elif path_specs and len(path_specs) > 1:
      path_specs_dicts = [path_spec.CopyToDict() for path_spec in path_specs]
      raise TurbiniaException(
          'Found more than one path_spec for {0:s} {1:s}: {2!s}'.format(
              self.parent_evidence.name, self.partition_location,
              path_specs_dicts))
    elif path_specs and len(path_specs) == 1:
      self.path_spec = path_specs[0]
      log.debug(
          'Found path_spec {0!s} for parent evidence {1:s}'.format(
              self.path_spec.CopyToDict(), self.parent_evidence.name))

    # In attaching a partition, we create a new loopback device using the
    # partition offset and size.
    if EvidenceState.ATTACHED in required_states or self.has_child_evidence:
      # Check for encryption
      encryption_type = partitions.GetPartitionEncryptionType(self.path_spec)
      if encryption_type:
        self.device_path = mount_local.PreprocessEncryptedVolume(
            self.parent_evidence.device_path,
            partition_offset=self.partition_offset,
            credentials=self.parent_evidence.credentials,
            encryption_type=encryption_type)
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
      if self.path_spec.type_indicator == 'APFS':
        self.mount_path = mount_local.PreprocessAPFS(
            self.device_path, self.parent_evidence.credentials)
      else:
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


class GoogleCloudDisk(Evidence):
  """Evidence object for a Google Cloud Disk.

  Attributes:
    project: The cloud project name this disk is associated with.
    zone: The geographic zone.
    disk_name: The cloud disk name.
  """

  REQUIRED_ATTRIBUTES = ['disk_name', 'project', 'zone']
  POSSIBLE_STATES = [EvidenceState.ATTACHED, EvidenceState.MOUNTED]

  def __init__(
      self, project=None, zone=None, disk_name=None, mount_partition=1, *args,
      **kwargs):
    """Initialization for Google Cloud Disk."""
    super(GoogleCloudDisk, self).__init__(*args, **kwargs)
    self.project = project
    self.zone = zone
    self.disk_name = disk_name
    self.mount_partition = mount_partition
    self.partition_paths = None
    self.cloud_only = True
    self.resource_tracked = True
    self.resource_id = self.disk_name
    self.device_path = None

  @property
  def name(self):
    if self._name:
      return self._name
    else:
      return ':'.join((self.type, self.project, self.disk_name))

  def _preprocess(self, _, required_states):
    # The GoogleCloudDisk should never need to be mounted unless it has child
    # evidence (GoogleCloudDiskRawEmbedded). In all other cases, the
    # DiskPartition evidence will be used. In this case we're breaking the
    # evidence layer isolation and having the child evidence manage the
    # mounting and unmounting.
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

  def __init__(
      self, embedded_path=None, project=None, zone=None, disk_name=None,
      mount_partition=1, *args, **kwargs):
    """Initialization for Google Cloud Disk containing a raw disk image."""
    super(GoogleCloudDiskRawEmbedded, self).__init__(
        project=project, zone=zone, disk_name=disk_name, mount_partition=1,
        *args, **kwargs)
    self.embedded_path = embedded_path
    # This Evidence needs to have a GoogleCloudDisk as a parent
    self.context_dependent = True

  @property
  def name(self):
    if self._name:
      return self._name
    else:
      return ':'.join((self.disk_name, self.embedded_path))

  def _preprocess(self, _, required_states):
    # Need to mount parent disk
    if not self.parent_evidence.partition_paths:
      self.parent_evidence.mount_path = mount_local.PreprocessMountPartition(
          self.parent_evidence.device_path, self.path_spec.type_indicator)
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
            f'Unable to find raw disk image {rawdisk_path:s} in GoogleCloudDisk'
        )
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
    super(PlasoFile, self).__init__(*args, **kwargs)
    self.save_metadata = True
    self.copyable = True
    self.plaso_version = plaso_version

  def _validate(self):
    """Validates whether the Plaso file contains any events.

    Raises:
      TurbiniaException: if validation fails.
    """
    cmd = [
        'pinfo',
        '--output-format',
        'json',
        '--sections',
        'events',
        self.local_path,
    ]
    total_file_events = 0

    try:
      log.info(f'Running pinfo to validate PlasoFile {self.local_path}')
      command = subprocess.run(cmd, capture_output=True, check=True)
      storage_counters_json = command.stdout.decode('utf-8').strip()
      # pinfo.py might print warnings so we only need to last line of output
      storage_counters_json = storage_counters_json.splitlines()[-1]
      storage_counters = json.loads(storage_counters_json)
      total_file_events = storage_counters.get('storage_counters', {}).get(
          'parsers', {}).get('total', 0)
      log.info(f'pinfo found {total_file_events} events.')
      if not total_file_events:
        raise TurbiniaException(
            'PlasoFile validation failed, pinfo found no events.')
    except (subprocess.CalledProcessError, FileNotFoundError) as exception:
      raise TurbiniaException(
          f'Error validating plaso file: {exception!s}') from exception
    except json.decoder.JSONDecodeError as exception:
      log.warning(
          f'Skipping validation, pinfo failed to read the Plaso '
          f'file: {exception!s}')


class PlasoCsvFile(Evidence):
  """Psort output file evidence.  """

  def __init__(self, plaso_version=None, *args, **kwargs):
    """Initialization for Plaso File evidence."""
    super(PlasoCsvFile, self).__init__(*args, **kwargs)
    self.save_metadata = False
    self.copyable = True
    self.plaso_version = plaso_version


# TODO(aarontp): Find a way to integrate this into TurbiniaTaskResult instead.
class ReportText(Evidence):
  """Text data for general reporting."""

  def __init__(self, text_data=None, *args, **kwargs):
    super(ReportText, self).__init__(*args, **kwargs)
    self.text_data = text_data
    self.copyable = True


class FinalReport(ReportText):
  """Report format for the final complete Turbinia request report."""

  def __init__(self, *args, **kwargs):
    super(FinalReport, self).__init__(*args, **kwargs)
    self.save_metadata = True


class TextFile(Evidence):
  """Text data."""

  def __init__(self, *args, **kwargs):
    super(TextFile, self).__init__(*args, **kwargs)
    self.copyable = True


class FilteredTextFile(TextFile):
  """Filtered text data."""
  pass


class BodyFile(Evidence):
  """Bodyfile data."""

  def __init__(self, *args, **kwargs):
    super(BodyFile, self).__init__(*args, **kwargs)
    self.copyable = True
    self.number_of_entries = None


class ExportedFileArtifact(Evidence):
  """Exported file artifact."""

  REQUIRED_ATTRIBUTES = ['artifact_name']

  def __init__(self, artifact_name=None, *args, **kwargs):
    """Initializes an exported file artifact."""
    super(ExportedFileArtifact, self).__init__(*args, **kwargs)
    self.artifact_name = artifact_name
    self.copyable = True


class ExportedFileArtifactLLM(Evidence):
  """Exported file artifact."""

  REQUIRED_ATTRIBUTES = ['artifact_name']

  def __init__(self, artifact_name=None, *args, **kwargs):
    """Initializes an exported file artifact."""
    super(ExportedFileArtifactLLM, self).__init__(*args, **kwargs)
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

  REQUIRED_ATTRIBUTES = ['source_path', 'module_list', 'profile']

  def __init__(
      self, source_path=None, module_list=None, profile=None, *args, **kwargs):
    """Initialization for raw memory evidence object."""
    super(RawMemory, self).__init__(source_path=source_path, *args, **kwargs)
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

  REQUIRED_ATTRIBUTES = ['container_id']
  POSSIBLE_STATES = [EvidenceState.CONTAINER_MOUNTED]

  def __init__(self, container_id=None, *args, **kwargs):
    """Initialization for Docker Container."""
    super(DockerContainer, self).__init__(*args, **kwargs)
    self.container_id = container_id
    self._container_fs_path = None
    self._docker_root_directory = None
    self.context_dependent = True

  @property
  def name(self):
    if self._name:
      return self._name
    else:
      if self.parent_evidence:
        return ':'.join((self.parent_evidence.name, self.container_id))
      else:
        return ':'.join((self.type, self.container_id))

  def _preprocess(self, _, required_states):
    if EvidenceState.CONTAINER_MOUNTED in required_states:
      from turbinia.lib.docker_manager import GetDockerPath
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


#TODO implement support for several ewf devices if there are more than one
#inside the ewf_mount_path
class EwfDisk(Evidence):
  """Evidence object for a EWF based evidence.

  Attributes:
    device_path (str): Path to a relevant 'raw' data source (ie: a block.
    ewf_path (str): Path to mounted EWF image.
    ewf_mount_path (str): Path to EWF mount directory.
  """
  REQUIRED_ATTRIBUTES = ['source_path']
  POSSIBLE_STATES = [EvidenceState.ATTACHED]

  def __init__(
      self, source_path=None, ewf_path=None, ewf_mount_path=None, *args,
      **kwargs):
    """Initialization for EWF evidence object."""
    super(EwfDisk, self).__init__(*args, **kwargs)
    self.source_path = source_path
    self.ewf_path = ewf_path
    self.ewf_mount_path = ewf_mount_path
    self.device_path = None

  def _preprocess(self, _, required_states):
    if EvidenceState.ATTACHED in required_states or self.has_child_evidence:
      if not self.ewf_path and not self.ewf_mount_path:
        self.ewf_mount_path = mount_local.PreprocessMountEwfDisk(
            self.source_path)
        self.ewf_path = mount_local.GetEwfDiskPath(self.ewf_mount_path)
      self.device_path = self.ewf_path
      self.local_path = self.ewf_path
      self.state[EvidenceState.ATTACHED] = True

  def _postprocess(self):
    if self.state[EvidenceState.ATTACHED]:
      self.state[EvidenceState.ATTACHED] = False
      mount_local.PostprocessUnmountPath(self.ewf_mount_path)


class ContainerdContainer(Evidence):
  """Evidence object for a containerd evidence.

  Attributes:
    namespace (str): Namespace of the container to be mounted.
    container_id (str): ID of the container to be mounted.
    _image_path (str): Path where disk image is mounted.
    _container_fs_path (str): Path where containerd filesystem is mounted.
  """
  REQUIRED_ATTRIBUTES = ['namespace', 'container_id']
  POSSIBLE_STATES = [EvidenceState.CONTAINER_MOUNTED]

  def __init__(
      self, namespace=None, container_id=None, image_name=None, pod_name=None,
      *args, **kwargs):
    """Initialization of containerd container."""
    super(ContainerdContainer, self).__init__(*args, **kwargs)
    self.namespace = namespace
    self.container_id = container_id
    self.image_name = image_name if image_name else 'UnknownImageName'
    self.pod_name = pod_name if pod_name else 'UnknownPodName'
    self._image_path = None
    self._container_fs_path = None

    self.context_dependent = True

  @property
  def name(self):
    if self._name:
      return self._name

    if self.parent_evidence:
      return ':'.join((
          self.parent_evidence.name, self.image_name, self.pod_name,
          self.container_id))
    else:
      return ':'.join(
          (self.type, self.image_name, self.pod_name, self.container_id))

  def _preprocess(self, _, required_states):
    if EvidenceState.CONTAINER_MOUNTED in required_states:
      self._image_path = self.parent_evidence.mount_path

      # Mount containerd container
      self._container_fs_path = containerd.PreprocessMountContainerdFS(
          self._image_path, self.namespace, self.container_id)
      self.mount_path = self._container_fs_path
      self.local_path = self.mount_path
      self.state[EvidenceState.CONTAINER_MOUNTED] = True

  def _postprocess(self):
    if self.state[EvidenceState.CONTAINER_MOUNTED]:
      # Unmount the container
      mount_local.PostprocessUnmountPath(self._container_fs_path)
      self.state[EvidenceState.CONTAINER_MOUNTED] = False
