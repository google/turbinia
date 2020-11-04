# -*- coding: utf-8 -*-
# Copyright 2020 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Task for enumerating partitions in a disk."""

from dfvfs.helpers import volume_scanner
from dfvfs.lib import errors as dfvfs_errors

from turbinia import TurbiniaException
from turbinia.evidence import RawDiskPartition
from turbinia.lib import dfvfs_classes
from turbinia.lib import text_formatter as fmt
from turbinia.workers import Priority
from turbinia.workers import TurbiniaTask


class PartitionEnumerationTask(TurbiniaTask):
  """Task to enumerate partitions in a disk."""

  def _ProcessPartition(self, path_spec):
    """Generate RawDiskPartition from a PathSpec.

    Args:
      path_spec (dfvfs.PathSpec): dfVFS path spec.

    Returns:
      A list of strings containing partition information to add to the status
      report.
    """
    status_report = []

    location = getattr(path_spec, 'location', None)
    if location in ('/', '\\'):
      path_spec = path_spec.parent
      location = getattr(path_spec, 'location', None)
    status_report.append(fmt.heading5('{0!s}:'.format(location)))
    # APFS volumes will have a volume_index
    volume_index = getattr(path_spec, 'volume_index', None)
    if not volume_index is None:
      status_report.append(
          fmt.bullet('Volume index: {0!s}'.format(volume_index)))
    # The part_index and start_offset come from the TSK partition
    # APFS volumes will have a TSK partition as a parent
    if not getattr(path_spec, 'part_index', None):
      path_spec = path_spec.parent
    status_report.append(
        fmt.bullet(
            'Partition index: {0!s}'.format(
                getattr(path_spec, 'part_index', None))))
    status_report.append(
        fmt.bullet(
            'Partition offset: {0!s}'.format(
                getattr(path_spec, 'start_offset', None))))
    return status_report

  def run(self, evidence, result):
    """Scan a raw disk for partitions.

    Args:
      evidence (Evidence object):  The evidence we will process.
      result (TurbiniaTaskResult): The object to place task results into.

    Returns:
      TurbiniaTaskResult object.
    """
    result.log('Scanning [{0:s}] for partitions'.format(evidence.local_path))

    success = False

    mediator = dfvfs_classes.UnattendedVolumeScannerMediator()
    try:
      scanner = volume_scanner.VolumeScanner(mediator=mediator)
      path_specs = scanner.GetBasePathSpecs(evidence.local_path)
      status_summary = 'Found {0:d} partition(s) in [{1:s}]:'.format(
          len(path_specs), evidence.local_path)
    except dfvfs_errors.ScannerError as e:
      status_summary = 'Error scanning for partitions: {0!s}'.format(e)

    status_report = [fmt.heading4(status_summary)]

    try:
      for path_spec in path_specs:
        status_report.extend(self._ProcessPartition(path_spec))
        partition_evidence = RawDiskPartition(
            source_path=evidence.local_path, path_spec=path_spec)
        result.add_evidence(partition_evidence, evidence.config)

      status_report = '\n'.join(status_report)
      success = True
    except TurbiniaException as e:
      status_summary = 'Error enumerating partitions: {0!s}'.format(e)
      status_report = status_summary

    result.log('Scanning of [{0:s}] is complete'.format(evidence.local_path))

    result.report_priority = Priority.LOW
    result.report_data = status_report
    result.close(self, success=success, status=status_summary)

    return result
