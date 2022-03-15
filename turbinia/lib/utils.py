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
"""Common utils."""

from __future__ import unicode_literals

import logging
import os
import subprocess
import tempfile
import threading

from turbinia import TurbiniaException

log = logging.getLogger('turbinia')

DEFAULT_TIMEOUT = 7200


def _image_export(command, output_dir, timeout=DEFAULT_TIMEOUT):
  """Runs image_export command.

  Args:
    file_name: Name of file (without path) to be extracted.
    output_dir: Path to directory to store the the extracted files.

  Returns:
    list: paths to extracted files.

  Raises:
    TurbiniaException: If an error occurs when running image_export.
  """
  # TODO: Consider using the exec helper to gather stdin/err.
  log.debug('Running image_export as [{0:s}]'.format(' '.join(command)))
  try:
    subprocess.check_call(command, timeout=timeout)
  except subprocess.CalledProcessError as e:
    raise TurbiniaException('image_export.py failed: {0!s}'.format(e))
  except subprocess.TimeoutExpired as e:
    raise TurbiniaException(
        'image_export.py timed out after {0:d}s: {1!s}'.format(timeout, e))

  collected_file_paths = []
  file_count = 0
  for dirpath, _, filenames in os.walk(output_dir):
    for filename in filenames:
      collected_file_paths.append(os.path.join(dirpath, filename))
      file_count += 1

  log.debug('Collected {0:d} files with image_export'.format(file_count))
  return collected_file_paths


def extract_artifacts(artifact_names, disk_path, output_dir, credentials=[]):
  """Extract artifacts using image_export from Plaso.

  Args:
    artifact_names: List of artifact definition names.
    disk_path: Path to either a raw disk image or a block device.
    output_dir: Path to directory to store the the extracted files.
    credentials: List of credentials to use for decryption.

  Returns:
    list: paths to extracted files.

  Raises:
    TurbiniaException: If an error occurs when running image_export.
  """
  # Plaso image_export expects artifact names as a comma separated string.
  artifacts = ','.join(artifact_names)
  image_export_cmd = [
      'sudo', 'image_export.py', '--artifact_filters', artifacts, '--write',
      output_dir, '--partitions', 'all', '--volumes', 'all', '--unattended'
  ]

  if credentials:
    for credential_type, credential_data in credentials:
      image_export_cmd.extend([
          '--credential', '{0:s}:{1:s}'.format(
              credential_type, credential_data)
      ])

  image_export_cmd.append(disk_path)

  return _image_export(image_export_cmd, output_dir)


def extract_files(file_name, disk_path, output_dir, credentials=[]):
  """Extract files using image_export from Plaso.

  Args:
    file_name: Name of file (without path) to be extracted.
    disk_path: Path to either a raw disk image or a block device.
    output_dir: Path to directory to store the the extracted files.
    credentials: List of credentials to use for decryption.

  Returns:
    list: paths to extracted files.

  Raises:
    TurbiniaException: If an error occurs when running image_export.
  """
  if not disk_path:
    raise TurbiniaException(
        'image_export.py failed: Attempted to run with no local_path')

  image_export_cmd = [
      'sudo', 'image_export.py', '--name', file_name, '--write', output_dir,
      '--partitions', 'all'
  ]

  if credentials:
    for credential_type, credential_data in credentials:
      image_export_cmd.extend([
          '--credential', '{0:s}:{1:s}'.format(
              credential_type, credential_data)
      ])

  image_export_cmd.append(disk_path)

  return _image_export(image_export_cmd, output_dir)


def get_exe_path(filename):
  """Gets the full path for a given executable.

  Args:
    filename (str): Executable name.

  Returns:
    (str|None): Full file path if it exists, else None
  """
  binary = None
  for path in os.environ['PATH'].split(os.pathsep):
    tentative_path = os.path.join(path, filename)
    if os.path.exists(tentative_path):
      binary = tentative_path
      break

  return binary


def bruteforce_password_hashes(
    password_hashes, tmp_dir, timeout=300, extra_args=''):
  """Bruteforce password hashes using Hashcat.

  Args:
    password_hashes (list): Password hashes as strings.
    tmp_dir (str): Path to use as a temporary directory
    timeout (int): Number of seconds to run for before terminating the process.
    extra_args (str): Any extra arguments to be passed to Hashcat.

  Returns:
    list: of tuples with hashes and plain text passwords.

  Raises:
    TurbiniaException if execution failed.
  """

  with tempfile.NamedTemporaryFile(delete=False, mode='w+') as fh:
    password_hashes_file_path = fh.name
    fh.write('\n'.join(password_hashes))

  pot_file = os.path.join((tmp_dir or tempfile.gettempdir()), 'hashcat.pot')
  password_list_file_path = os.path.expanduser('~/password.lst')

  # Fallback
  if not os.path.isfile(password_list_file_path):
    password_list_file_path = '/usr/share/john/password.lst'

  # Bail
  if not os.path.isfile(password_list_file_path):
    raise TurbiniaException('No password list available')

  cmd = ['hashcat', '--force', '-a', '0']
  if extra_args:
    cmd = cmd + extra_args.split(' ')
  cmd = cmd + ['--potfile-path={}'.format(pot_file)]
  cmd = cmd + [password_hashes_file_path, password_list_file_path]

  with open(os.devnull, 'w') as devnull:
    try:
      child = subprocess.Popen(cmd, stdout=devnull, stderr=devnull)
      timer = threading.Timer(timeout, child.terminate)
      timer.start()
      child.communicate()
      # Cancel the timer if the process is done before the timer.
      if timer.is_alive():
        timer.cancel()
    except OSError as e:
      raise TurbiniaException('hashcat failed: {0}'.format(str(e)))

  result = []

  if os.path.isfile(pot_file):
    with open(pot_file, 'r') as fh:
      for line in fh:
        password_hash, plaintext = line.rsplit(':', 1)
        plaintext = plaintext.rstrip()
        if plaintext:
          result.append((password_hash, plaintext))
    os.remove(pot_file)

  return result
