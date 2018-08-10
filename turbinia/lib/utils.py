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


def get_artifacts(artifact_names, disk_path, output_dir):
  """Extract artifacts from the disk using image_export from Plaso.

  Args:
    artifact_names: List of artifact definition names.
    disk_path: Path to either a raw disk image or a device.
    output_dir: Path to directory to store the the extracted files.

  Returns:
    Dictionary with of file names and paths to extracted files.
  """
  # Plaso image_export expects artifact names as a comma separated string.
  artifacts = ','.join(artifact_names)

  # Generate the command we want to run.
  cmd = [
    'image_export.py',
    '--artifact_filters', artifacts,
    '--write', output_dir,
    disk_path
  ]

  # TODO(jberggren) Catch any errors here.
  subprocess.call(cmd)

  # List all files collected, excluding directories.
  files = []
  for dir_path, _, file_names in os.walk(output_dir):
    for file_name in file_names:
      files.append(os.path.join(dir_path, file_name))

  return files
