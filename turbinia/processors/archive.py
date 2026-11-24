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

import os
import tarfile
import logging

from time import time
from turbinia import TurbiniaException

log = logging.getLogger(__name__)


def _ValidateTarMember(tar_info, uncompressed_directory):
  """Validate that a tar member is safe and extracts inside the target dir.

  Args:
    tar_info (tarfile.TarInfo): Metadata for the tar member.
    uncompressed_directory (str): The target extraction directory.

  Raises:
    TurbiniaException: If the tar member is a disallowed type or could write
        outside the target extraction directory.
  """
  # Reject link members outright. Because validation runs before extraction
  # (when the target directory is empty), realpath-based checks on link
  # targets are purely lexical and can be bypassed by chaining symlinks
  # inside the archive. Evidence archives have no need for links.
  if tar_info.issym() or tar_info.islnk():
    raise TurbiniaException(
        f'Tar file contains a link member which is not permitted: '
        f'{tar_info.name:s}')

  if not (tar_info.isreg() or tar_info.isdir()):
    raise TurbiniaException(
        f'Tar file contains an unsupported member type: {tar_info.name:s}')

  if os.path.isabs(tar_info.name):
    raise TurbiniaException(
        f'Tar file member path is absolute and not permitted: '
        f'{tar_info.name:s}')

  base_directory = os.path.realpath(uncompressed_directory)
  member_path = os.path.realpath(os.path.join(base_directory, tar_info.name))

  if os.path.commonpath([base_directory, member_path]) != base_directory:
    raise TurbiniaException(
        f'Tar file member path is outside the extraction directory: '
        f'{tar_info.name:s}')


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
        f'The File or Directory does not exist: {compressed_directory:s}')

  # TODO(wyassine): rewrite this check so it is not dependent
  # on a list of hard coded extensions and instead have a
  # check to determine whether or not it is a tar file format.
  if not (compressed_directory.endswith('.tgz') or
          compressed_directory.endswith('.tar.gz')):
    raise TurbiniaException(
        'The file is not a supported format. The list of '
        'acceptable extensions are: .tgz or .tar.gz')


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
        f'The File or Directory does not exist: {uncompressed_directory:s}')

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
    raise TurbiniaException(f'An error has occurred: {exception!s}')
  except tarfile.TarError as exception:
    raise TurbiniaException(
        f'An error has while compressing the directory: {exception!s}')
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
    with tarfile.TarFile.open(compressed_directory) as tar:
      for tar_info in tar.getmembers():
        _ValidateTarMember(tar_info, uncompressed_directory)
      tar.extractall(path=uncompressed_directory, filter='data')
    log.info(
        'The tar file has been uncompressed to the following directory: {0:s}'
        .format(uncompressed_directory))
  except IOError as exception:
    raise TurbiniaException(f'An error has occurred: {exception!s}')
  except tarfile.TarError as exception:
    raise TurbiniaException(
        f'An error has occurred while uncompressing the tar file: {exception!s}'
    )
  return uncompressed_directory
