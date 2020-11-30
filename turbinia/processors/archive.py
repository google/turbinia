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
"""File archiving processor"""

from __future__ import unicode_literals

import os
import tarfile
import logging

from time import time
from turbinia import TurbiniaException

log = logging.getLogger('turbinia')


def ValidateTarFile(compressed_directory):
  """ Validates a given compressed directory path.

  Performs a check to determine if the path exists and if
  the file extension is in the list of accepted extensions.

  Args:
    compressed_directory(str): The path to the compressed tar file.

  Raises:
    TurbiniaException: If validation fails.
  """
  if not os.path.exists(compressed_directory):
    raise TurbiniaException(
        'The File or Directory does not exist: {0:s}'.format(
            compressed_directory))

  # TODO(wyassine): rewrite this check so it is not dependant
  # on a list of hard coded extensions and instead have a
  # check to determine whether or not it is a tar file format.
  if not (compressed_directory.endswith('.tgz') or
          compressed_directory.endswith('.tar.gz')):
    raise TurbiniaException(
        'The file is not a supported format. The list of '
        'acceptable exensions are: .tgz or .tar.gz')


def CompressDirectory(uncompressed_directory, output_path=None):
  """Compress a given directory into a tar file.

  Args:
    uncompressed_directory(str): The path to the uncompressed directory.
    output_path(str): The path to compress the directory into.

  Returns:
    str: The path to the tar file.
  """
  # Error handling check for a non-existent file or directory.
  if not os.path.exists(uncompressed_directory):
    raise TurbiniaException(
        'The File or Directory does not exist: {0:s}'.format(
            uncompressed_directory))

  # Iterate through a given list of files and compress them.
  compressed_directory = uncompressed_directory + '.tar.gz'
  if output_path:
    output_file = compressed_directory.split('/')[-1]
    compressed_directory = os.path.join(output_path, output_file)
  try:
    with tarfile.TarFile.open(compressed_directory, 'w:gz') as tar:
      tar.add(uncompressed_directory, arcname='')
      tar.close()
      log.info(
          'The tar file has been created and '
          'can be found at: {0:s}'.format(compressed_directory))
  except IOError as exception:
    raise TurbiniaException('An error has occurred: {0!s}'.format(exception))
  except tarfile.TarError as exception:
    raise TurbiniaException(
        'An error has while compressing the directory: {0!s}'.format(exception))
  return compressed_directory


def UncompressTarFile(compressed_directory, output_tmp):
  """Uncompress a provided tar file.

  Args:
    compressed_directory(str): The path to the tar file.
    output_tmp(str): The path to the temporary directory that the
                      uncompressed tar file will be placed into.

  Returns:
    str: The path to the uncompressed directory.
  """
  # Tar file validation check
  ValidateTarFile(compressed_directory)

  # Generate the uncompressed directory path
  uncompressed_file = 'uncompressed-' + str(int(time()))
  uncompressed_directory = os.path.join(output_tmp, uncompressed_file)

  # Uncompress the tar file into the uncompressed directory.
  try:
    tar = tarfile.TarFile.open(compressed_directory)
    tar.extractall(path=uncompressed_directory)
    tar.close()
    log.info(
        'The tar file has been uncompressed to the following directory: {0:s}'
        .format(uncompressed_directory))
  except IOError as exception:
    raise TurbiniaException('An error has occurred: {0!s}'.format(exception))
  except tarfile.TarError as exception:
    raise TurbiniaException(
        'An error has occurred while uncompressing the tar '
        'file: {0!s}'.format(exception))
  return uncompressed_directory
