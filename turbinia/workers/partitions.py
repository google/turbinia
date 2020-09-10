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
from turbinia.evidence import RawDiskPartition
from turbinia.lib.dfvfs_classes import SourceAnalyzer
from turbinia.workers import Priority
from turbinia.workers import TurbiniaTask


class PartitionEnumerationTask(TurbiniaTask):
  """Task to enumerate partitions in a disk."""

  def run(self, evidence, result):
    """Scan a raw disk for partitions.

    Args:
        evidence (Evidence object):  The evidence we will process.
        result (TurbiniaTaskResult): The object to place task results into.

    Returns:
        TurbiniaTaskResult object.
    """
    result.log('Scanning [{0:s}]'.format(evidence.local_path))

    success = False

    source_analyzer = SourceAnalyzer()
    volumes = source_analyzer.VolumeScan(evidence.local_path)

    try:
      status_report = []
      status_report.append(
          'Found {0:d} partition(s) in [{1:s}]:\n'.format(
              len(volumes), evidence.local_path))
      status_report.append(
          '{0:<15}{1:<30}{2:<10}{3:>15}{4:>15}   {5:<30}'.format(
              'Identifier', 'Description', 'Type', 'Offset (bytes)',
              'Size (bytes)', 'Name (APFS)'))

      for identifier, volume in volumes.items():
        volume_type = ''
        description = ''
        offset = ''
        size = ''
        name = ''

        if 'volume_type' in volume:
          volume_type = volume['volume_type']
        if 'description' in volume:
          description = volume['description']
        if 'offset' in volume:
          offset = volume['offset']
        if 'size' in volume:
          size = volume['size']
        if 'name' in volume:
          name = volume['name']

        status_report.append(
            '{0:<15}{1:<30}{2:<10}{3:>15}{4:>15}   {5:<30}'.format(
                identifier, description, volume_type, offset, size, name))

        partition_evidence = RawDiskPartition(
            source_path=evidence.local_path, volume_identifier=identifier,
            offset=offset, size=size)
        result.add_evidence(partition_evidence, evidence.config)

      status_report = '\n'.join(status_report)
      success = True
    except TurbiniaException as e:
      status_report = 'Error enumerating partitions: {0!s}'.format(e)

    result.log('Scanning of [{0:s}] is complete'.format(evidence.local_path))

    result.report_priority = Priority.LOW
    result.report_data = status_report
    result.close(self, success=success, status=status_report)

    return result
