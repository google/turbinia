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

import logging

from turbinia import config
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

    from turbinia.processors import mount_local
    from turbinia.processors import partitions
  except ImportError as exception:
    message = f'Could not import dfVFS libraries: {exception!s}'
    raise TurbiniaException(message)

log = logging.getLogger(__name__)


class PartitionEnumerationTask(TurbiniaTask):
  """Task to enumerate partitions in a disk."""

  REQUIRED_STATES = [EvidenceState.ATTACHED]

  # Task configuration variables from recipe
  TASK_CONFIG = {
      # Process important partitions
      'process_important': True,
      # Process unimportant partitions
      'process_unimportant': False,
      # Minimum important partition size (default 100M)
      'minimum_size': 104857600
  }

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

    location = None
    volume_index = None
    partition_index = None
    partition_offset = None
    partition_size = None
    lv_uuid = None
    important = True

    child_path_spec = path_spec
    is_lvm = False
    # File system location / identifier
    location = self._GetLocation(path_spec)
    container_location = None
    log.debug(
        'Got location {0:s} for path_spec {1!s} with type {2:s}'.format(
            location, path_spec.CopyToDict(), path_spec.type_indicator))
    while child_path_spec.HasParent():
      type_indicator = child_path_spec.type_indicator
      log.debug(f'Path spec type: {type_indicator:s}')

      if type_indicator == dfvfs_definitions.TYPE_INDICATOR_APFS_CONTAINER:
        # APFS volume index
        volume_index = getattr(child_path_spec, 'volume_index', None)
        # Since APFS can't be attached, we'll need to look for a container
        if child_path_spec.HasParent():
          container_location = getattr(child_path_spec.parent, 'location', None)
          log.debug(f'Container location: {container_location!s}')
          # We only need the container if it's a partition, else we'll attach
          # the whole disk
          if container_location and container_location[:2] != '/p':
            container_location = None

      if type_indicator in (dfvfs_definitions.TYPE_INDICATOR_GPT,
                            dfvfs_definitions.TYPE_INDICATOR_LVM,
                            dfvfs_definitions.TYPE_INDICATOR_TSK_PARTITION):
        # Partition index
        partition_index = getattr(child_path_spec, 'part_index', None)

        if type_indicator == dfvfs_definitions.TYPE_INDICATOR_TSK_PARTITION:
          volume_system = tsk_volume_system.TSKVolumeSystem()
        elif type_indicator == dfvfs_definitions.TYPE_INDICATOR_LVM:
          is_lvm = True
          volume_system = lvm_volume_system.LVMVolumeSystem()
        else:
          volume_system = gpt_volume_system.GPTVolumeSystem()
        try:
          volume_system.Open(child_path_spec)
          if container_location:
            volume_identifier = container_location.replace('/', '')
          else:
            volume_identifier = location.replace('/', '')
          volume = volume_system.GetVolumeByIdentifier(volume_identifier)

          if is_lvm:
            # LVM Logical Volume UUID
            lv_uuid = volume.GetAttribute('identifier')
            if lv_uuid:
              lv_uuid = lv_uuid.value

          partition_offset = volume.extents[0].offset
          partition_size = volume.extents[0].size
        except dfvfs_errors.VolumeSystemError as exception:
          raise TurbiniaException(f'Could not process partition: {exception!s}')
        break

      child_path_spec = child_path_spec.parent

    # Is partition important based on filesystem?
    if path_spec.type_indicator not in ('APFS', 'EXT', 'HFS', 'NTFS', 'TSK',
                                        'XFS'):
      important = False
      log.info(
          'Marking partition {0:s} unimportant (filesystem {1:s})'.format(
              location, path_spec.type_indicator))

    # Is partition important based on size? (100M or larger)
    minimum_size = self.task_config.get('minimum_size')
    if partition_size and partition_size < minimum_size:
      important = False
      log.info(
          'Marking partition {0:s} unimportant (size {1!s} < {2!s})'.format(
              location, partition_size, minimum_size))

    # If LVM, we need to deactivate the Volume Group
    if lv_uuid:
      mount_local.PostprocessDeleteLosetup(None, lv_uuid=lv_uuid)

    status_report.append(fmt.heading5(f'{location!s}:'))
    status_report.append(fmt.bullet(f'Important: {important!s}'))
    status_report.append(
        fmt.bullet(f'Filesystem: {path_spec.type_indicator!s}'))
    if volume_index is not None:
      status_report.append(fmt.bullet(f'Volume index: {volume_index!s}'))
    if partition_index is not None:
      status_report.append(fmt.bullet(f'Partition index: {partition_index!s}'))
      status_report.append(
          fmt.bullet(f'Partition offset: {partition_offset!s}'))
      status_report.append(fmt.bullet(f'Partition size: {partition_size!s}'))
    if volume_index is None and partition_index is None:
      status_report.append(fmt.bullet('Source evidence is a volume image'))

    # Not setting path_spec here as it will need to be generated for each task
    partition_evidence = DiskPartition(
        partition_location=location, partition_offset=partition_offset,
        partition_size=partition_size, lv_uuid=lv_uuid, important=important)

    log.debug(
        'Created DiskPartition evidence with location {0:s}, offset {1!s}, and size {2!s}'
        .format(location, partition_offset, partition_size))

    return partition_evidence, status_report

  def run(self, evidence, result):
    """Scan a raw disk for partitions.

    Args:
      evidence (Evidence object):  The evidence we will process.
      result (TurbiniaTaskResult): The object to place task results into.

    Returns:
      TurbiniaTaskResult object.
    """
    config.LoadConfig()
    process_important = self.task_config.get('process_important')
    process_unimportant = self.task_config.get('process_unimportant')

    result.log(f'Scanning [{evidence.name:s}] for partitions')

    path_specs = []
    success = False
    processing = 0

    try:
      path_specs = partitions.Enumerate(evidence)
      status_summary = f'Found {len(path_specs):d} partition(s) in [{evidence.name:s}]'

      # Debug output
      path_spec_debug = ['Base path specs:']
      for path_spec in path_specs:
        path_spec_types = [path_spec.type_indicator]
        child_path_spec = path_spec
        while child_path_spec.HasParent():
          path_spec_types.insert(0, child_path_spec.parent.type_indicator)
          child_path_spec = child_path_spec.parent
        path_spec_debug.append(
            ' | '.join(
                (f'{path_spec.CopyToDict()!s}', ' -> '.join(path_spec_types))))
      log.debug('\n'.join(path_spec_debug))
    except dfvfs_errors.ScannerError as exception:
      status_summary = f'Error scanning for partitions: {exception!s}'

    status_report = [fmt.heading4(status_summary)]

    try:
      for path_spec in path_specs:
        partition_evidence, partition_status = self._ProcessPartition(path_spec)
        status_report.extend(partition_status)
        if ((process_important and partition_evidence.important) or
            (process_unimportant and not partition_evidence.important)):
          result.add_evidence(partition_evidence, evidence.config)
          processing += 1
        else:
          log.info(
              'Not processing {0:s} partition {1!s} due to task config'.format(
                  'important' if partition_evidence.important else
                  'unimportant', partition_evidence.name))

      status_report = '\n'.join(status_report)
      success = True
    except TurbiniaException as exception:
      status_summary = f'Error enumerating partitions: {exception!s}'
      status_report = status_summary

    result.log(f'Scanning of [{evidence.name:s}] is complete')
    status_summary = ' '.join((
        status_summary, 'Processing {0!s} partition{1:s}:'.format(
            processing, '' if processing == 1 else 's')))

    result.report_priority = Priority.LOW
    result.report_data = status_report
    result.close(self, success=success, status=status_summary)

    return result
