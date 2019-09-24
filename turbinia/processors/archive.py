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


def CompressDirectory(uncompressed_directory):
  """Compress a given directory into a tar file.

  Args:
    uncompressed_directory(str): The path to the uncompressed directory.

  Returns:
    str: The path to the tar file.
  """
  # Error handling check for a non-existent file or directory.
  if not os.path.exists(uncompressed_directory):
    raise TurbiniaException(
        'The File or Directory does not exist: {0:s}'.format(
            uncompressed_directory))

  # Iterate through a given list of files and compress them.
  file_names = os.listdir(uncompressed_directory)
  compressed_directory = uncompressed_directory + '.tar.gz'
  try:
    with tarfile.TarFile.open(compressed_directory, 'w:gz') as tar:
      for f in file_names:
        tar.add(os.path.join(uncompressed_directory, f), arcname=f)
      tar.close()
      log.info(
          'The tar file has been created and '
          'can be found at: {0:s}'.format(compressed_directory))
  except IOError as exception:
    raise TurbiniaException('An error has occured: {0:s}'.format(exception))
  except tarfile.CompressionError as e:
    raise TurbiniaException(
        'An error has occured during compression: {0:s}'.format(e))
  return compressed_directory


def UncompressTarFile(compressed_directory):
  """Uncompress a provided tar file.

  Args:
    compressed_directory(str): The path to the tar file.

  Returns:
    str: The path to the uncompressed directory.
  """
  # Error handling check for a non-existent file or directory.
  if not os.path.exists(compressed_directory):
    raise TurbiniaException(
        'The File or Directory does not exist: {0:s}'.format(
            compressed_directory))

  # Check if file extension is in list of accepted extensions.
  # TODO(wyassine): rewrite this check so it is not dependant
  # on a list of hard coded extensions and instead have a
  # check to determine whether or not it is a tar file format.
  accepted_extensions = ['.tar.gz', '.tgz']
  if not any(ext in compressed_directory for ext in accepted_extensions):
    raise TurbiniaException(
        'The file is not a supported format. The list of '
        'acceptable exensions are: {0:s}'.format(','.join(accepted_extensions)))

  # Path files will be extracted to.
  uncompressed_directory = compressed_directory.strip(
      ''.join(accepted_extensions))

  # Check to see if directory exists and adjust if needed.
  if os.path.exists(uncompressed_directory):
    log.info(
        'The extraction path {0:s} already exists. Appending the '
        'current timestamp to file name.'.format(uncompressed_directory))
    # Retrieve current time to append to end of file.
    timest = int(time())
    uncompressed_directory = uncompressed_directory + '-' + str(timest)

  # Uncompress the tar file.
  try:
    tar = tarfile.TarFile.open(compressed_directory)
    tar.extractall(path=uncompressed_directory)
    tar.close()
    log.info(
        'The tar file has been uncompressed to the following directory: {0:s}'
        .format(uncompressed_directory))
  except IOError as exception:
    raise TurbiniaException('The file is not readable: {0:s}'.format(exception))
  except tarfile.ExtractError as e:
    raise TurbiniaException(
        'An error has occured during extraction: {0:s}'.format(e))
  return uncompressed_directory
