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

import os
import subprocess
import tempfile
import threading

from turbinia import TurbiniaException


def extract_artifacts(artifact_names, disk_path, output_dir):
  """Extract artifacts using image_export from Plaso.

  Args:
    artifact_names: List of artifact definition names.
    disk_path: Path to either a raw disk image or a block device.
    output_dir: Path to directory to store the the extracted files.

  Returns:
    dict: file names and paths to extracted files.
  """
  # Plaso image_export expects artifact names as a comma separated string.
  artifacts = ','.join(artifact_names)

  image_export_cmd = [
      'image_export.py', '--artifact_filters', artifacts, '--write', output_dir,
      '--partitions', 'all', disk_path
  ]

  # TODO: Consider break the exec helper to gather stdin/err.
  try:
    subprocess.check_call(image_export_cmd)
  except subprocess.CalledProcessError:
    raise TurbiniaException('image_export.py failed.')

  collected_file_paths = []
  for dirpath, _, filenames in os.walk(output_dir):
    for filename in filenames:
      collected_file_paths.append(os.path.join(dirpath, filename))

  return collected_file_paths


def bruteforce_password_hashes(password_hashes, timeout=300):
  """Bruteforce password hashes using John the Ripper.

  Args:
    password_hashes (list): Password hashes as strings.
    timeout (int): Number of seconds to run for before terminating the process.

  Returns:
    list: of tuples with hashes and plain text passwords.

  Raises:
    TurbiniaException if execution failed.
  """

  with tempfile.NamedTemporaryFile(delete=False) as fh:
    password_hashes_file_path = fh.name
    fh.write('\n'.join(password_hashes))

  cmd = ['john', password_hashes_file_path]

  with open(os.devnull, 'w') as devnull:
    try:
      child = subprocess.Popen(cmd, stdout=devnull, stderr=devnull)
      timer = threading.Timer(timeout, child.terminate)
      timer.start()
      child.communicate()
      # Cancel the timer if the process is done before the timer.
      if timer.is_alive():
        timer.cancel()
    except OSError:
      raise TurbiniaException('john the ripper failed.')

  result = []
  # Default location of the result file, no way to change it.
  pot_file = os.path.expanduser('~/.john/john.pot')

  if os.path.isfile(pot_file):
    with open(pot_file, 'r') as fh:
      for line in fh.readlines():
        password_hash, plaintext = line.rsplit(':', 1)
        result.append((password_hash, plaintext.rstrip()))
    os.remove(pot_file)

  return result
