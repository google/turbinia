# -*- coding: utf-8 -*-
# Copyright 2022 Google Inc.
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
"""Task to run dfimagetools FileEntryLister on disk partitions."""
from __future__ import unicode_literals

import os

from turbinia import TurbiniaException
from turbinia.workers import TurbiniaTask
from turbinia.evidence import EvidenceState as state
from turbinia.evidence import BodyFile

if TurbiniaTask.check_worker_role():
  try:
    from dfvfs.helpers import volume_scanner
    from dfimagetools import file_entry_lister
  except ImportError as exception:
    message = 'Could not import libraries: {0!s}'.format(exception)
    raise TurbiniaException(message)


class FileSystemTimelineTask(TurbiniaTask):

  REQUIRED_STATES = [state.ATTACHED]

  def run(self, evidence, result):
    """Task to execute (dfimagetools) FileEntryLister.

    Args:
        evidence (Evidence object):  The evidence we will process.
        result (TurbiniaTaskResult): The object to place task results into.

    Returns:
        TurbiniaTaskResult object.
    """
    bodyfile_output = os.path.join(self.output_dir, 'file_system.bodyfile')
    output_evidence = BodyFile(source_path=bodyfile_output)
    number_of_entries = 0

    # Set things up for the FileEntryLister client. We will scan all
    # partitions in the volume.
    volume_scanner_options = volume_scanner.VolumeScannerOptions()
    volume_scanner_options.partitions = ['all']

    # Create the FileEntryLister client and generate the path specs
    # for all available partitions.
    entry_lister = file_entry_lister.FileEntryLister()
    base_path_specs = entry_lister.GetBasePathSpecs(
        evidence.device_path, options=volume_scanner_options)

    # Iterate over all file entries and generate the output in bodyfile
    # format.
    try:
      with open(bodyfile_output, 'w') as file_object:
        for file_entry, path_segments in entry_lister.ListFileEntries(
            base_path_specs):
          bodyfile_entries = entry_lister.GetBodyfileEntries(
              file_entry, path_segments)
          for bodyfile_entry in bodyfile_entries:
            file_object.write(bodyfile_entry)
            file_object.write('\n')
            number_of_entries += 1
      output_evidence.number_of_entries = number_of_entries
      result.add_evidence(output_evidence, evidence.config)
      status = 'Successfully generated file system timeline at [{0:s}]'.format(
          bodyfile_output)
      result.close(self, success=True, status=status)
    except TurbiniaException as exception:
      result.log(exception)
      status = 'Error generating bodyfile {0!s}'.format(exception)
      result.close(self, success=False, status=status)

    return result
