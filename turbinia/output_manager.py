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

from google.cloud import storage

log = logging.getLogger('turbinia')


class OutputManager(object):
  """Manages output data.

  Manages the configured output writers.  Also saves and retrieves evidence data
  as well as other files that are created when running tasks.

  Attributes:
    _output_writers (list): The configured output writers
  """

  def __init__(self, result):
    self._output_writers = self.get_output_writers(result)

  def get_output_writers(self, result):
    """Get a list of output writers.

    Args:
      result: A TurbiniaTaskResult object

    Returns:
      A list of OutputWriter objects.
    """
    epoch = str(int(time.time()))
    unique_dir = '{0:s}-{1:s}-{2:s}'.format(
        epoch, str(result.task_id), result.task_name)

    writers = [LocalOutputWriter(base_output_dir=result.base_output_dir,
                                 unique_dir=unique_dir)]
    config.LoadConfig()
    if config.GCS_OUTPUT_PATH:
      writer = GCSOutputWriter(
          unique_dir=unique_dir, gcs_path=config.GCS_OUTPUT_PATH)
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
    if not hasattr(writer, 'output_dir'):
      raise TurbiniaException(
          'Local output writer does not have output_dir attribute.')

    if not writer.output_dir:
      raise TurbiniaException(
          'Local output writer attribute output_dir is not set')

    return writer.output_dir

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

    return (saved_path, saved_path_type)


class OutputWriter(object):
  """Base class.

  By default this will write the files the Evidence objects point to along with
  any other files expclicitly written with copy_to().

  Attributes:
    base_output_dir (string): The base path for output
    name (string): Name of this output writer
    unique_dir (string): A psuedo-unique string to be used in paths.
  """

  def __init__(self, unique_dir=None):
    """Initialization for OutputWriter."""
    self.unique_dir = unique_dir
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
  """Class for writing to local filesystem output.

  Attributes:
    output_dir: The full path for output.
  """

  def __init__(self, base_output_dir=None, *args, **kwargs):
    self.base_output_dir = base_output_dir
    self.output_dir = None
    super(LocalOutputWriter, self).__init__(*args, **kwargs)
    self.name = 'LocalWriter'

  def create_output_dir(self):
    self.output_dir = os.path.join(self.base_output_dir, self.unique_dir)
    if not os.path.exists(self.output_dir):
      try:
        log.info('Creating new directory {0:s}'.format(self.output_dir))
        os.makedirs(self.output_dir)
      except OSError as e:
        if e.errno == errno.EACCESS:
          msg = 'Permission error ({0:s})'.format(str(e))
        else:
          msg = str(e)
        raise TurbiniaException(msg)

    return self.output_dir

  def _copy(self, file_path):
    """Copies file to local output dir.

    Args:
      file_: A string path to a source file.

    Returns:
      The path the file was saved to, or None if file was not written.
    """
    output_file = os.path.join(self.output_dir, os.path.basename(file_path))
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

  def __init__(self, gcs_path=None, *args, **kwargs):
    """Initialization for GCSOutputWriter.

    Args:
      gcs_path (string): GCS path to put output results into.
    """
    super(GCSOutputWriter, self).__init__(*args, **kwargs)
    self.name = 'GCSWriter'
    config.LoadConfig()
    self.client = storage.Client(project=config.PROJECT)

    match = re.search(r'gs://(.*)/(.*)', gcs_path)
    if not match:
      raise TurbiniaException(
          'Cannot find bucket and path from GCS config {0:s}'.format(gcs_path))
    self.bucket = match.group(1)
    self.base_output_dir = match.group(2)

  def create_output_dir(self):
    # Directories in GCS are artificial, so any path can be written as part of
    # the object name.
    pass

  def copy_to(self, file_):
    bucket = self.client.get_bucket(self.bucket)
    full_path = os.path.join(
        self.base_output_dir, self.unique_dir, os.path.basename(file_))
    log.info('Writing {0:s} to GCS path {1:s}'.format(file_, full_path))
    blob = storage.Blob(full_path, bucket)
    blob.upload_from_filename(file_, client=self.client)
    return os.path.join('gs://', self.bucket, full_path)

  def copy_from(self, file_):
    bucket = self.client.get_bucket(self.bucket)
    full_path = os.path.join(
        self.base_output_dir, self.unique_dir, os.path.basename(file_))
    log.info('Writing GCS file {0:s} to local path {1:s}'.format(
        file_, full_path))
    blob = storage.Blob(full_path, bucket)
    blob.download_to_filename(file_, client=self.client)
    return full_path
