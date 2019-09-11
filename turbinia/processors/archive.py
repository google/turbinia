# -*- coding: utf-8 -*-
# Copyright 2019 Google Inc.
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
"""Processor for compressing and decompressing directories."""

from __future__ import unicode_literals

import os
import tarfile
import logging

from turbinia import TurbiniaException

log = logging.getLogger('turbinia')


def CompressFolder(local_path):
  """Compress a given directory into a gzip file.

  Args:
    local_path(str): The path to the directory.

  Returns:
    str: The path to the gzip file.
  """
  # Check if the File or Directory exists.
  if not os.path.exists(local_path):
    raise TurbiniaException(
        'The File or Directory does not exist: {0:s}'.format(local_path))

  # Iterate through a given list of files and compress them.
  file_names = os.listdir(local_path)
  archive_path = local_path + '.tar.gz'
  try:
    with tarfile.TarFile.open(archive_path, 'w:gz') as tar:
      for f in file_names:
        tar.add(os.path.join(local_path, f), arcname=f)
      tar.close()
      log.info('The gzip file has been created and can be found: {0:s}'.\
        format(archive_path))
  except tarfile.CompressionError as e:
    raise TurbiniaException(
        'An error has occured during compression: {0:s}'.format(e))
  return archive_path


def DecompressArchive(local_path):
  """Decompress a provided gzip file.

  Args:
    local_path(str): The path to the gzip file.

  Returns:
    str: The path to the uncompressed directory.
  """
  extract_path = local_path.strip('.tar.gz')

  try:
    # Check if it is a tar file and extract contents if true.
    tar = tarfile.TarFile.open(local_path)
    tar.extractall(extract_path)
    tar.close()
    log.info(
        'The file has been decompressed to the following\
      directory: {0:s}'.format(extract_path))
  except IOError as e:
    raise TurbiniaException(
        'The file is not a readable gzip format: {0:s}'.format(e))
  except tarfile.ExtractError as e:
    raise TurbiniaException(
        'An error has occured during extraction: {0:s}'.format(e))
  return extract_path
