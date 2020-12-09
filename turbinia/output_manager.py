# -*- coding: utf-8 -*-
# Copyright 2018 Google Inc.
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
"""Classes to write output to various location types."""

from __future__ import unicode_literals

import errno
import json
import logging
import os
import re
import shutil
import time

from turbinia import config
from turbinia import TurbiniaException

config.LoadConfig()
if config.GCS_OUTPUT_PATH and config.GCS_OUTPUT_PATH.lower() != 'none':
  from google.cloud import storage
  from google.cloud import exceptions

log = logging.getLogger('turbinia')


class OutputManager:
  """Manages output data.

  Manages the configured output writers.  Also saves and retrieves evidence data
  as well as other files that are created when running tasks.

  Attributes:
    _output_writers (list): The configured output writers
    is_setup (bool): Whether this object has been setup or not.
  """

  def __init__(self):
    self._output_writers = None
    self.is_setup = False

  @staticmethod
  def get_output_writers(name, uid, remote_only):
    """Get a list of output writers.

    Args:
      name (str): The name of the Request or Task.
      uid (str): The unique identifier of the Request or Task.

    Returns:
      A list of OutputWriter objects.
    """
    config.LoadConfig()
    epoch = str(int(time.time()))
    unique_dir = '{0:s}-{1:s}-{2:s}'.format(epoch, str(uid), name)
    writers = []
    local_output_dir = None

    if not remote_only:
      writer = LocalOutputWriter(
          base_output_dir=config.OUTPUT_DIR, unique_dir=unique_dir)
      writers.append(writer)
      local_output_dir = writers[0].local_output_dir

    if config.GCS_OUTPUT_PATH:
      writer = GCSOutputWriter(
          unique_dir=unique_dir, gcs_path=config.GCS_OUTPUT_PATH,
          local_output_dir=local_output_dir)
      writers.append(writer)
    return writers

  def get_local_output_dirs(self):
    """Gets the local output directories from the local output writer.

    Returns:
      Tuple(string): (Path to temp directory, path to local output directory)

    Raises:
      TurbiniaException: If no local output writer with output_dir is found.
    """
    if not self._output_writers:
      raise TurbiniaException('No output writers found.')

    # Get the local writer
    writer = [w for w in self._output_writers if w.name == 'LocalWriter'][0]
    if not hasattr(writer, 'local_output_dir'):
      raise TurbiniaException(
          'Local output writer does not have local_output_dir attribute.')

    if not writer.local_output_dir:
      raise TurbiniaException(
          'Local output writer attribute local_output_dir is not set')

    if not hasattr(writer, 'tmp_dir'):
      raise TurbiniaException(
          'Local output writer does not have tmp_dir attribute.')

    if not writer.tmp_dir:
      raise TurbiniaException(
          'Local output writer attribute tmp_dir is not set')

    return (writer.tmp_dir, writer.local_output_dir)

  def retrieve_evidence(self, evidence_):
    """Retrieves evidence data from remote location.

    Args:
      evidence_: Evidence object

    Returns:
      An evidence object
    """
    for writer in self._output_writers:
      if writer.name == evidence_.saved_path_type:
        log.info(
            'Retrieving copyable evidence data from {0:s}'.format(
                evidence_.saved_path))
        evidence_.source_path = writer.copy_from(evidence_.saved_path)
    return evidence_

  def save_evidence(self, evidence_, result=None):
    """Saves local evidence data to remote location.

    Args:
      evidence_ (Evidence): Evidence to save data from
      result (TurbiniaTaskResult): Result object to save path data to

    Returns:
      An evidence object

    Raises:
      TurbiniaException: If serialization or writing of evidence config fails
    """
    path, path_type, local_path = self.save_local_file(
        evidence_.source_path, result)

    if evidence_.save_metadata:
      metadata = evidence_.config.copy()
      metadata['evidence_path'] = path
      metadata_path = '{0:s}.metadata.json'.format(local_path)
      try:
        json_str = json.dumps(metadata)
      except TypeError as exception:
        raise TurbiniaException(
            'Could not serialize Evidence config for {0:s}: {1!s}'.format(
                evidence_.name, exception))

      try:
        log.debug('Writing metadata file to {0:s}'.format(metadata_path))
        with open(metadata_path, 'wb') as file_handle:
          file_handle.write(json_str.encode('utf-8'))
      except IOError as exception:
        raise TurbiniaException(
            'Could not write metadata file {0:s}: {1!s}'.format(
                metadata_path, exception))

      self.save_local_file(metadata_path, result)

    # Set the evidence local_path from the saved path info so that in cases
    # where tasks are saving evidence into the temp dir, we'll get the newly
    # copied version from the saved output path.
    if local_path:
      evidence_.source_path = local_path
    evidence_.saved_path = path
    evidence_.saved_path_type = path_type
    if evidence_.saved_path:
      log.info(
          'Saved copyable evidence data to {0:s}'.format(evidence_.saved_path))
    return evidence_

  def save_local_file(self, file_, result):
    """Saves local file by writing to all output writers.

    Most local files will already be in the local output directory and won't
    need to be copied by the LocalOutputWriter, but any files outside of this
    directory (e.g. files in the tmp_dir) will still be copied locally.

    Args:
      file_ (string): Path to file to save.
      result (TurbiniaTaskResult): Result object to save path data to

    Returns:
      Tuple of (String of last written file path,
                String of last written file destination output type,
                Local path if saved locally, else None)
    """
    saved_path = None
    saved_path_type = None
    local_path = None
    for writer in self._output_writers:
      new_path = writer.copy_to(file_)
      if new_path:
        saved_path = new_path
        saved_path_type = writer.name
      if result:
        if new_path:
          result.saved_paths.append(new_path)
        elif os.path.exists(file_) and os.path.getsize(file_) > 0:
          # We want to save the old path if the path is still valid.
          result.saved_paths.append(file_)

      if writer.name == LocalOutputWriter.NAME:
        local_path = new_path

    return saved_path, saved_path_type, local_path

  def setup(self, name, uid, remote_only=False):
    """Setup OutputManager object."""
    self._output_writers = self.get_output_writers(name, uid, remote_only)
    self.is_setup = True


class OutputWriter:
  """Base class.

  By default this will write the files the Evidence objects point to along with
  any other files explicitly written with copy_to().

  Attributes:
    base_output_dir (string): The base path for output.  The value is specific
        to the output writer object type.
    local_output_dir: The full path for the local output dir.
    name (string): Name of this output writer
    unique_dir (string): A psuedo-unique string to be used in paths.
  """

  NAME = 'base_output_writer'

  def __init__(
      self, base_output_dir=None, unique_dir=None, local_output_dir=None):
    """Initialization for OutputWriter.

    Args:
      base_output_dir (string): The base path for output.  Set to the configured
          OUTPUT_DIR by default.
      local_output_dir: The full path for the local output dir.  This will be
          generated automatically if not set.
      unique_dir (string):  A psuedo-unique string to be used in paths. This
          will be generated automatically if not set.
    """
    self.unique_dir = unique_dir
    self.name = self.NAME

    if base_output_dir:
      self.base_output_dir = base_output_dir
    else:
      config.LoadConfig()
      self.base_output_dir = config.OUTPUT_DIR

    if local_output_dir:
      self.local_output_dir = local_output_dir
    else:
      self.local_output_dir = self.create_output_dir()

  def create_output_dir(self, base_path=None):
    """Creates a unique output path for this task and creates directories.

    Needs to be run at runtime so that the task creates the directory locally.

    Args:
      base_path(string): Base directory output directory will be created in.

    Returns:
      A local output path string.

    Raises:
      TurbiniaException: If there are failures creating the directory.
    """
    raise NotImplementedError

  def copy_to(self, source_file):
    """Copies file to the managed location.

    Files will be copied into base_output_dir with a filename set to the
    basename of the source file.

    Args:
      source_file (string): A path to a local source file.

    Returns:
      The path the file was saved to, or None if file was not written.

    Raises:
      TurbiniaException: When the source file is empty or there are problems
          saving the file.
    """
    raise NotImplementedError

  def copy_from(self, source_file):
    """Copies output file from the managed location to the local output dir.

    Args:
      source_file (string): A path to a source file in the managed storage
          location.  This path should be in a format matching the storage type
          (e.g. GCS paths are formatted like 'gs://bucketfoo/' and local paths
          are like '/foo/bar'.

    Returns:
      The path the file was saved to, or None if file was not written.

    Raises:
      TurbiniaException: When there are problems copying from storage.
    """
    raise NotImplementedError


class LocalOutputWriter(OutputWriter):
  """Class for writing to local filesystem output.

  Attributes:
    tmp_dir (string): Path to temp directory
  """

  NAME = 'LocalWriter'

  # pylint: disable=keyword-arg-before-vararg
  def __init__(self, base_output_dir=None, *args, **kwargs):
    super(LocalOutputWriter, self).__init__(
        base_output_dir=base_output_dir, *args, **kwargs)
    config.LoadConfig()
    self.tmp_dir = self.create_output_dir(base_path=config.TMP_DIR)

  def create_output_dir(self, base_path=None):
    base_path = base_path if base_path else self.base_output_dir
    output_dir = os.path.join(base_path, self.unique_dir)
    if not os.path.exists(output_dir):
      try:
        log.debug('Creating new directory {0:s}'.format(output_dir))
        os.makedirs(output_dir)
      except OSError as exception:
        if exception.errno == errno.EACCES:
          message = 'Permission error ({0:s})'.format(str(exception))
        else:
          message = str(exception)
        raise TurbiniaException(message)

    return output_dir

  def _copy(self, file_path):
    """Copies file to local output dir.

    Args:
      file_path(string): Source path to the file to copy.

    Returns:
      The path the file was saved to, or None if file was not written.
    """
    destination_file = os.path.join(
        self.local_output_dir, os.path.basename(file_path))

    if self.local_output_dir in os.path.commonprefix([file_path,
                                                      destination_file]):
      log.debug(
          'Not copying source file {0:s} already in output dir {1:s}'.format(
              file_path, self.local_output_dir))
      return None
    if not os.path.exists(file_path):
      log.warning('Source file [{0:s}] does not exist.'.format(file_path))
      return None
    if os.path.exists(destination_file):
      log.warning(
          'Target output file path [{0:s}] already exists.'.format(
              destination_file))
      return None

    shutil.copy(file_path, destination_file)
    log.debug('Copied file {0:s} to {1:s}'.format(file_path, destination_file))
    return destination_file

  def copy_to(self, source_file):
    return self._copy(source_file)

  def copy_from(self, source_file):
    return self._copy(source_file)


class GCSOutputWriter(OutputWriter):
  """Output writer for Google Cloud Storage.

  attributes:
    bucket (string): Storage bucket to put output results into.
    client (google.cloud.storage.Client): GCS Client
  """

  CHUNK_SIZE = 10 * (2**20)  # 10MB by default

  NAME = 'GCSWriter'

  def __init__(self, gcs_path, *args, **kwargs):
    """Initialization for GCSOutputWriter.

    Args:
      gcs_path (string): GCS path to put output results into.
    """
    super(GCSOutputWriter, self).__init__(*args, **kwargs)
    config.LoadConfig()
    self.client = storage.Client(project=config.TURBINIA_PROJECT)

    self.bucket, self.base_output_dir = self._parse_gcs_path(gcs_path)

  @staticmethod
  def _parse_gcs_path(file_):
    """Get the bucket and path values from a GCS path.

    Args:
      file_ (string): GCS file path.

    Returns:
      A tuple of ((string) bucket, (string) path)
    """
    match = re.search(r'gs://(.*?)/(.*$)', file_)
    if not match:
      raise TurbiniaException(
          'Cannot find bucket and path from GCS config {0:s}'.format(file_))
    return match.group(1), match.group(2)

  def create_output_dir(self, base_path=None):
    # Directories in GCS are artificial, so any path can be written as part of
    # the object name.
    pass

  def copy_to(self, source_path):
    if os.path.getsize(source_path) == 0:
      message = (
          'Local source file {0:s} is empty.  Not uploading to GCS'.format(
              source_path))
      log.error(message)
      raise TurbiniaException(message)

    bucket = self.client.get_bucket(self.bucket)
    destination_path = os.path.join(
        self.base_output_dir, self.unique_dir, os.path.basename(source_path))
    log.info(
        'Writing {0:s} to GCS path {1:s}'.format(source_path, destination_path))
    try:
      blob = storage.Blob(destination_path, bucket, chunk_size=self.CHUNK_SIZE)
      blob.upload_from_filename(source_path, client=self.client)
    except exceptions.GoogleCloudError as exception:
      message = 'File upload to GCS failed: {0!s}'.format(exception)
      log.error(message)
      raise TurbiniaException(message)
    return os.path.join('gs://', self.bucket, destination_path)

  def copy_from(self, source_path):
    """Copies output file from the managed location to the local output dir.

    Args:
      source_file (string): A path to a source file in the managed storage
          location.  This path should be in a format matching the storage type
          (e.g. GCS paths are formatted like 'gs://bucketfoo/' and local paths
          are like '/foo/bar'.

    Returns:
      The path the file was saved to, or None if file was not written.

    Raises:
      TurbiniaException: If file retrieval fails.
    """
    bucket = self.client.get_bucket(self.bucket)
    gcs_path = self._parse_gcs_path(source_path)[1]
    destination_path = os.path.join(
        self.local_output_dir, os.path.basename(source_path))
    log.info(
        'Writing GCS file {0:s} to local path {1:s}'.format(
            source_path, destination_path))
    try:
      blob = storage.Blob(gcs_path, bucket, chunk_size=self.CHUNK_SIZE)
      blob.download_to_filename(destination_path, client=self.client)
    except exceptions.RequestRangeNotSatisfiable as exception:
      message = (
          'File retrieval from GCS failed, file may be empty: {0!s}'.format(
              exception))
      log.error(message)
      raise TurbiniaException(message)
    except exceptions.GoogleCloudError as exception:
      message = 'File retrieval from GCS failed: {0!s}'.format(exception)
      log.error(message)
      raise TurbiniaException(message)

    if not os.path.exists(destination_path):
      message = (
          'File retrieval from GCS failed: Local file {0:s} does not '
          'exist'.format(destination_path))
      log.error(message)
      raise TurbiniaException(message)
    return destination_path
