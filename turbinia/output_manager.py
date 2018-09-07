# -*- coding: utf-8 -*-
# Copyright 2015 Google Inc.
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
import logging
import os
import re
import shutil
import time

from turbinia import config
from turbinia import TurbiniaException

config.LoadConfig()
if config.TASK_MANAGER == 'PSQ':
  from google.cloud import storage

log = logging.getLogger('turbinia')


class OutputManager(object):
  """Manages output data.

  Manages the configured output writers.  Also saves and retrieves evidence data
  as well as other files that are created when running tasks.

  Attributes:
    _output_writers (list): The configured output writers
  """

  def __init__(self):
    self._output_writers = None

  @staticmethod
  def get_output_writers(task):
    """Get a list of output writers.

    Args:
      task: A TurbiniaTask object

    Returns:
      A list of OutputWriter objects.
    """
    epoch = str(int(time.time()))
    unique_dir = '{0:s}-{1:s}-{2:s}'.format(
        epoch, str(task.id), task.name)

    writers = [LocalOutputWriter(base_output_dir=task.base_output_dir,
                                 unique_dir=unique_dir)]
    local_output_dir = writers[0].local_output_dir
    config.LoadConfig()
    if config.GCS_OUTPUT_PATH:
      writer = GCSOutputWriter(
          unique_dir=unique_dir, gcs_path=config.GCS_OUTPUT_PATH,
          local_output_dir=local_output_dir)
      writers.append(writer)
    return writers

  def get_local_output_dir(self):
    """Gets the local output dir from the local output writer.

    Returns:
      String to locally created output directory.

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

    return writer.local_output_dir

  def retrieve_evidence(self, evidence_):
    """Retrieves evidence data from remote location.

    Args:
      evidence_: Evidence object

    Returns:
      An evidence object
    """
    for writer in self._output_writers:
      if writer.name == evidence_.saved_path_type:
        log.info('Retrieving copyable evidence data from {0:s}'.format(
            evidence_.saved_path))
        evidence_.local_path = writer.copy_from(evidence_.saved_path)
    return evidence_

  def save_evidence(self, evidence_, result):
    """Saves local evidence data to remote location.

    Args:
      evidence_ (Evidence): Evidence to save data from
      result (TurbiniaTaskResult): Result object to save path data to

    Returns:
      An evidence object
    """
    (path, path_type) = self.save_local_file(evidence_.local_path, result)
    evidence_.saved_path = path
    evidence_.saved_path_type = path_type
    log.info('Saved copyable evidence data to {0:s}'.format(
        evidence_.saved_path))
    return evidence_

  def save_local_file(self, file_, result):
    """Saves local file by writing to all non-local output writers.

    Args:
      file_ (string): Path to file to save.
      result (TurbiniaTaskResult): Result object to save path data to

    Returns:
      Tuple of (String of last written file path,
                String of last written file destination output type)
    """
    saved_path = None
    saved_path_type = None
    for writer in self._output_writers:
      if writer.name != 'LocalOutputWriter':
        new_path = writer.copy_to(file_)
        if new_path:
          result.saved_paths.append(new_path)
          saved_path = new_path
          saved_path_type = writer.name

    return saved_path, saved_path_type

  def setup(self, task):
    """Setup OutputManager object."""
    self._output_writers = self.get_output_writers(task)


class OutputWriter(object):
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

  def __init__(self, base_output_dir=None, unique_dir=None,
               local_output_dir=None):
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
    self.local_output_dir = local_output_dir
    self.name = self.NAME
    if base_output_dir:
      self.base_output_dir = base_output_dir
    else:
      config.LoadConfig()
      self.base_output_dir = config.OUTPUT_DIR
    self.create_output_dir()

  def create_output_dir(self):
    """Creates a unique output path for this task and creates directories.

    Needs to be run at runtime so that the task creates the directory locally.

    Returns:
      A local output path string.

    Raises:
      TurbiniaException: If there are failures creating the directory.
    """
    raise NotImplementedError

  def copy_to(self, file_):
    """Copies output file to the managed location.

    Args:
      file_: A string path to a source file.

    Returns:
      The path the file was saved to, or None if file was not written.
    """
    raise NotImplementedError

  def copy_from(self, file_):
    """Copies output file from the managed location.

    Args:
      file_: A string path to a source file.

    Returns:
      The path the file was saved to, or None if file was not written.
    """
    raise NotImplementedError


class LocalOutputWriter(OutputWriter):
  """Class for writing to local filesystem output."""

  NAME = 'LocalWriter'

  def __init__(self, base_output_dir=None, *args, **kwargs):
    super(LocalOutputWriter, self).__init__(base_output_dir=base_output_dir,
                                            *args, **kwargs)

  def create_output_dir(self):
    self.local_output_dir = os.path.join(self.base_output_dir, self.unique_dir)
    if not os.path.exists(self.local_output_dir):
      try:
        log.info('Creating new directory {0:s}'.format(self.local_output_dir))
        os.makedirs(self.local_output_dir)
      except OSError as e:
        if e.errno == errno.EACCES:
          msg = 'Permission error ({0:s})'.format(str(e))
        else:
          msg = str(e)
        raise TurbiniaException(msg)

    return self.local_output_dir

  def _copy(self, file_path):
    """Copies file to local output dir.

    Args:
      file_path: A string path to a source file.

    Returns:
      The path the file was saved to, or None if file was not written.
    """
    output_file = os.path.join(self.local_output_dir,
                               os.path.basename(file_path))
    if not os.path.exists(file_path):
      log.warning('File [{0:s}] does not exist.'.format(file_path))
      return None
    if os.path.exists(output_file):
      log.warning('New file path [{0:s}] already exists.'.format(output_file))
      return None

    shutil.copy(file_path, output_file)
    return output_file

  def copy_to(self, file_path):
    return self._copy(file_path)

  def copy_from(self, file_path):
    return self._copy(file_path)


class GCSOutputWriter(OutputWriter):
  """Output writer for Google Cloud Storage.

  attributes:
    bucket (string): Storage bucket to put output results into.
    client (google.cloud.storage.Client): GCS Client
  """

  CHUNK_SIZE = 10 * (2 ** 20)  # 10MB by default

  NAME = 'GCSWriter'

  def __init__(self, gcs_path, *args, **kwargs):
    """Initialization for GCSOutputWriter.

    Args:
      gcs_path (string): GCS path to put output results into.
    """
    super(GCSOutputWriter, self).__init__(*args, **kwargs)
    config.LoadConfig()
    self.client = storage.Client(project=config.PROJECT)

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

  def create_output_dir(self):
    # Directories in GCS are artificial, so any path can be written as part of
    # the object name.
    pass

  def copy_to(self, file_):
    bucket = self.client.get_bucket(self.bucket)
    full_path = os.path.join(
        self.base_output_dir, self.unique_dir, os.path.basename(file_))
    log.info('Writing {0:s} to GCS path {1:s}'.format(file_, full_path))
    blob = storage.Blob(full_path, bucket, chunk_size=self.CHUNK_SIZE)
    blob.upload_from_filename(file_, client=self.client)
    return os.path.join('gs://', self.bucket, full_path)

  def copy_from(self, file_):
    bucket = self.client.get_bucket(self.bucket)
    gcs_path = self._parse_gcs_path(file_)[1]
    full_path = os.path.join(self.local_output_dir, os.path.basename(file_))
    log.info('Writing GCS file {0:s} to local path {1:s}'.format(
        file_, full_path))
    blob = storage.Blob(gcs_path, bucket, chunk_size=self.CHUNK_SIZE)
    blob.download_to_filename(full_path, client=self.client)
    if not os.path.exists(full_path):
      raise TurbiniaException(
          'File retrieval from GCS failed: Local file {0:s} does not '
          'exist'.format(full_path))
    return full_path
