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
from dfvfs.lib import definitions as dfvfs_definitions
from dfvfs.lib import errors as dfvfs_errors
from dfvfs.volume import tsk_volume_system

from turbinia import TurbiniaException
from turbinia.evidence import RawDiskPartition
from turbinia.lib import dfvfs_classes
from turbinia.lib import text_formatter as fmt
from turbinia.workers import Priority
from turbinia.workers import TurbiniaTask


class PartitionEnumerationTask(TurbiniaTask):
  """Task to enumerate partitions in a disk."""

  def _ProcessPartition(self, evidence_path, path_spec):
    """Generate RawDiskPartition from a PathSpec.

    Args:
      evidence_path (str): Local path of the parent evidence
      path_spec (dfvfs.PathSpec): dfVFS path spec.

    Returns:
      A new RawDiskPartition evidence item and a list of strings containing
      partition information to add to the status report.
    """
    status_report = []

    fs_path_spec = path_spec
    fs_location = None
    partition_location = None
    volume_index = None
    partition_index = None
    partition_offset = None
    partition_size = None

    # File system location / identifier
    fs_location = getattr(path_spec, 'location', None)
    while path_spec.HasParent():
      type_indicator = path_spec.type_indicator
      if type_indicator == dfvfs_definitions.TYPE_INDICATOR_APFS_CONTAINER:
        # APFS volume index
        volume_index = getattr(path_spec, 'volume_index', None)

      if type_indicator == dfvfs_definitions.TYPE_INDICATOR_TSK_PARTITION:
        if fs_location in ('\\', '/'):
          # Partition location / identifier
          fs_location = getattr(path_spec, 'location', None)
        partition_location = getattr(path_spec, 'location', None)
        # Partition index
        partition_index = getattr(path_spec, 'part_index', None)

        volume_system = tsk_volume_system.TSKVolumeSystem()
        try:
          volume_system.Open(path_spec)
          volume_identifier = partition_location.replace('/', '')
          volume = volume_system.GetVolumeByIdentifier(volume_identifier)

          partition_offset = volume.extents[0].offset
          partition_size = volume.extents[0].size
        except dfvfs_errors.VolumeSystemError as e:
          raise TurbiniaException(
              'Could not process partition: {0!s}'.format(e))
        break

      path_spec = path_spec.parent

    status_report.append(fmt.heading5('{0!s}:'.format(fs_location)))
    if partition_index:
      if not volume_index is None:
        status_report.append(
            fmt.bullet('Volume index: {0!s}'.format(volume_index)))
      status_report.append(
          fmt.bullet('Partition index: {0!s}'.format(partition_index)))
      status_report.append(
          fmt.bullet('Partition offset: {0!s}'.format(partition_offset)))
      status_report.append(
          fmt.bullet('Partition size: {0!s}'.format(partition_size)))
    else:
      status_report.append(fmt.bullet('Source evidence is a volume image'))

    partition_evidence = RawDiskPartition(
        source_path=evidence_path, path_spec=fs_path_spec,
        partition_offset=partition_offset, partition_size=partition_size)

    return partition_evidence, status_report

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
        partition_evidence, partition_status = self._ProcessPartition(
            evidence.local_path, path_spec)
        status_report.extend(partition_status)
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
