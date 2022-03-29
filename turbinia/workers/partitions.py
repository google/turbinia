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

from turbinia import TurbiniaException
from turbinia.evidence import DiskPartition
from turbinia.evidence import EvidenceState
from turbinia.lib import text_formatter as fmt
from turbinia.workers import Priority
from turbinia.workers import TurbiniaTask

if TurbiniaTask.check_worker_role():
  try:
    from dfvfs.lib import definitions as dfvfs_definitions
    from dfvfs.lib import errors as dfvfs_errors
    from dfvfs.volume import gpt_volume_system
    from dfvfs.volume import lvm_volume_system
    from dfvfs.volume import tsk_volume_system

    from turbinia.processors import partitions
  except ImportError as exception:
    message = 'Could not import dfVFS libraries: {0!s}'.format(exception)
    raise TurbiniaException(message)


class PartitionEnumerationTask(TurbiniaTask):
  """Task to enumerate partitions in a disk."""

  REQUIRED_STATES = [EvidenceState.ATTACHED]

  def _GetLocation(self, path_spec):
    """Retrieve the best location for a partition.

    Args:
      path_spec (dfvfs.PathSpec): dfVFS path spec.

    Returns:
      The location attribute for the partition.
    """
    location = getattr(path_spec, 'location', None)
    if location and location not in ('\\', '/'):
      return location
    while path_spec.HasParent():
      path_spec = path_spec.parent
      new_location = getattr(path_spec, 'location', None)
      if new_location and new_location not in ('\\', '/'):
        type_indicator = path_spec.type_indicator
        if type_indicator in dfvfs_definitions.VOLUME_SYSTEM_TYPE_INDICATORS:
          return new_location
    return location

  def _ProcessPartition(self, path_spec):
    """Generate RawDiskPartition from a PathSpec.

    Args:
      path_spec (dfvfs.PathSpec): dfVFS path spec.

    Returns:
      A new RawDiskPartition evidence item and a list of strings containing
      partition information to add to the status report.
    """
    status_report = []

    fs_path_spec = path_spec
    location = None
    volume_index = None
    partition_index = None
    partition_offset = None
    partition_size = None
    lv_uuid = None

    # File system location / identifier
    is_lvm = False
    location = self._GetLocation(path_spec)
    while path_spec.HasParent():
      type_indicator = path_spec.type_indicator
      if type_indicator == dfvfs_definitions.TYPE_INDICATOR_APFS_CONTAINER:
        # APFS volume index
        volume_index = getattr(path_spec, 'volume_index', None)

      if type_indicator in (dfvfs_definitions.TYPE_INDICATOR_GPT,
                            dfvfs_definitions.TYPE_INDICATOR_LVM,
                            dfvfs_definitions.TYPE_INDICATOR_TSK_PARTITION):
        # Partition index
        partition_index = getattr(path_spec, 'part_index', None)

        if type_indicator == dfvfs_definitions.TYPE_INDICATOR_TSK_PARTITION:
          volume_system = tsk_volume_system.TSKVolumeSystem()
        elif type_indicator == dfvfs_definitions.TYPE_INDICATOR_LVM:
          is_lvm = True
          volume_system = lvm_volume_system.LVMVolumeSystem()
        else:
          volume_system = gpt_volume_system.GPTVolumeSystem()
        try:
          volume_system.Open(path_spec)
          volume_identifier = location.replace('/', '')
          volume = volume_system.GetVolumeByIdentifier(volume_identifier)

          if is_lvm:
            # LVM Logical Volume UUID
            lv_uuid = volume.GetAttribute('identifier')
            if lv_uuid:
              lv_uuid = lv_uuid.value

          partition_offset = volume.extents[0].offset
          partition_size = volume.extents[0].size
        except dfvfs_errors.VolumeSystemError as e:
          raise TurbiniaException(
              'Could not process partition: {0!s}'.format(e))
        break

      path_spec = path_spec.parent

    status_report.append(fmt.heading5('{0!s}:'.format(location)))
    status_report.append(
        fmt.bullet('Filesystem: {0!s}'.format(fs_path_spec.type_indicator)))
    if volume_index is not None:
      status_report.append(
          fmt.bullet('Volume index: {0!s}'.format(volume_index)))
    if partition_index is not None:
      status_report.append(
          fmt.bullet('Partition index: {0!s}'.format(partition_index)))
      status_report.append(
          fmt.bullet('Partition offset: {0!s}'.format(partition_offset)))
      status_report.append(
          fmt.bullet('Partition size: {0!s}'.format(partition_size)))
    if volume_index is None and partition_index is None:
      status_report.append(fmt.bullet('Source evidence is a volume image'))

    # Not setting path_spec here as it will need to be generated for each task
    partition_evidence = DiskPartition(
        partition_location=location, partition_offset=partition_offset,
        partition_size=partition_size, lv_uuid=lv_uuid)

    return partition_evidence, status_report

  def run(self, evidence, result):
    """Scan a raw disk for partitions.

    Args:
      evidence (Evidence object):  The evidence we will process.
      result (TurbiniaTaskResult): The object to place task results into.

    Returns:
      TurbiniaTaskResult object.
    """
    # TODO(dfjxs): Use evidence name instead of evidence_description (#718)
    evidence_description = None
    if hasattr(evidence, 'embedded_path'):
      evidence_description = ':'.join(
          (evidence.disk_name, evidence.embedded_path))
    elif hasattr(evidence, 'disk_name'):
      evidence_description = evidence.disk_name
    else:
      evidence_description = evidence.source_path

    result.log('Scanning [{0:s}] for partitions'.format(evidence_description))

    path_specs = []
    success = False

    try:
      path_specs = partitions.Enumerate(evidence)
      status_summary = 'Found {0:d} partition(s) in [{1:s}]:'.format(
          len(path_specs), evidence_description)
    except dfvfs_errors.ScannerError as e:
      status_summary = 'Error scanning for partitions: {0!s}'.format(e)

    status_report = [fmt.heading4(status_summary)]

    try:
      for path_spec in path_specs:
        partition_evidence, partition_status = self._ProcessPartition(path_spec)
        status_report.extend(partition_status)
        result.add_evidence(partition_evidence, evidence.config)

      status_report = '\n'.join(status_report)
      success = True
    except TurbiniaException as e:
      status_summary = 'Error enumerating partitions: {0!s}'.format(e)
      status_report = status_summary

    result.log('Scanning of [{0:s}] is complete'.format(evidence_description))

    result.report_priority = Priority.LOW
    result.report_data = status_report
    result.close(self, success=success, status=status_summary)

    return result
