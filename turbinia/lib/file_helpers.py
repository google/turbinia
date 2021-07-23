# -*- coding: utf-8 -*-
# Copyright 2020 Google Inc.
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
"""Library containing file helpers."""

import os
import logging
from tempfile import NamedTemporaryFile

log = logging.getLogger('turbinia')


def file_to_str(file_path):
  """Read file to variable

  Args:
    file_path(str): Path to file to be read into variable.

  Returns:
    str: contents of the file. Empty string if there is an error.
  """
  file_contents = ''
  if not os.path.exists(file_path):
    log.error('File {0:s} not found.'.format(file_path))
  else:
    try:
      file_contents = open(file_path).read()
    except IOError as e:
      log.error('Cannot open file {0:s} [{1!s}]'.format(file_path, e))
  return file_contents


def file_to_list(file_path):
  """Read file to list line by line

  Args:
    file_path(str): Path to file to be read into list

  Returns:
    list[str]: The parsed strings. Empty list if there is an error.
  """
  try:
    with open(file_path) as fh:
      content = fh.readlines()
      return [x.rstrip() for x in content]
  except IOError as e:
    log.error('Cannot open file {0:s} [{1!s}]'.format(file_path, e))
  return []


def write_str_to_temp_file(source, preferred_dir=None):
  """Creates a temporary file with the contents of a specified string variable.

  Args:
    source (str): String to be written to file.
    preferred_dir(str): Path to the preferred directory.

  Returns:
    str: File name for newly created temporary file.
    None: If there is an error.
  """
  try:
    with NamedTemporaryFile(dir=preferred_dir, delete=False, mode='w') as fh:
      fh.write(source)
      return fh.name
  except IOError as e:
    log.error('Could not write to temporary file. [{1!s}]'.format(e))
  return None


def write_list_to_temp_file(entries, preferred_dir=None):
  """Creates a file containing a line-by-line list of strings.

  Args:
    entries (list): List of entries to be written line by line.
    preferred_dir(str): Path to the preferred directory.

  Returns:
    str: Path to newly created file.
    None: If there is an error.
  """
  try:
    with NamedTemporaryFile(dir=preferred_dir, delete=False, mode='w') as fh:
      fh.write('\n'.join(entries))
      return fh.name
  except:
    log.error(
        'Could not write entries [{0!s}] to temporary file.'.format(entries))
  return None
