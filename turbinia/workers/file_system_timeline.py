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
    from dfvfs.lib import errors as dfvfs_errors
    from dfimagetools import file_entry_lister
  except ImportError as exception:
    message = 'Could not import libraries: {0!s}'.format(exception)
    raise TurbiniaException(message)


class FileSystemTimelineTask(TurbiniaTask):
  """Task to generate file system timelines. """

  REQUIRED_STATES = [state.ATTACHED]

  TASK_CONFIG = {'partitions': ['all']}

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
    volume_scanner_options.partitions = self.task_config.get('partitions')

    # Create the FileEntryLister client and generate the path specs
    # for all available partitions.
    entry_lister = file_entry_lister.FileEntryLister()
    try:
      base_path_specs = entry_lister.GetBasePathSpecs(
          evidence.device_path, options=volume_scanner_options)
    except dfvfs_errors.ScannerError as exception:
      status = 'Unable to open evidence: {0!s}'.format(exception)
      result.close(self, success=False, status=status)
      return result

    # Iterate over all file entries and generate the output in bodyfile
    # format.
    try:
      bodyfile_fileobj = open(bodyfile_output, 'w', encoding='utf-8')
    except IOError as exception:
      status = 'Failed to open local output file: {0!s}'.format(exception)
      result.close(self, success=False, status=status)
      return result

    file_entries = enumerate(entry_lister.ListFileEntries(base_path_specs))
    while file_entries:
      try:
        _, (file_entry, path_segments) = next(file_entries)
        bodyfile_entries = entry_lister.GetBodyfileEntries(
            file_entry, path_segments)
        for bodyfile_entry in bodyfile_entries:
          bodyfile_fileobj.write(bodyfile_entry)
          bodyfile_fileobj.write('\n')
          number_of_entries += 1
      except StopIteration:
        break
      except (dfvfs_errors.AccessError, dfvfs_errors.BackEndError,
              dfvfs_errors.MountPointError, dfvfs_errors.PathSpecError,
              IOError) as exception:
        status = 'Unable to process file entry: {0!s}'.format(exception)
        result.log(status)

    bodyfile_fileobj.close()

    if number_of_entries > 0:
      output_evidence.number_of_entries = number_of_entries
      result.add_evidence(output_evidence, evidence.config)
      status = 'Generated file system timeline containing [{0:d}] entries'.format(
          number_of_entries)
      result.close(self, success=True, status=status)
    else:
      status = 'Unable to process any file entries.'
      result.close(self, success=False, status=status)

    return result
