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

from dfvfs.lib import definitions as dfvfs_definitions

from turbinia import TurbiniaException
from turbinia.evidence import RawDiskPartition
from turbinia.lib.dfvfs_classes import SourceAnalyzer
from turbinia.workers import Priority
from turbinia.workers import TurbiniaTask


class PartitionEnumerationTask(TurbiniaTask):
  """Task to enumerate partitions in a disk."""

  def _ProcessPartition(self, path_spec):
    """Generate RawDiskPartition from a PathSpec.

    Args:
      path_spec (dfvfs.PathSpec): dfVFS path spec.
    """
    status_report = []

    location = getattr(path_spec, 'location', None)
    if location in ('/', '\\'):
      path_spec = path_spec.parent
      location = getattr(path_spec, 'location', None)
    status_report.append('{0!s}:'.format(location))
    if getattr(path_spec, 'volume_index', None):
      status_report.append('\tVolume index: {0!s}'.format(
          getattr(path_spec, 'volume_index', None)))
    if not getattr(path_spec, 'part_index', None):
      path_spec = path_spec.parent
    status_report.append('\tPartition index: {0!s}'.format(
        getattr(path_spec, 'part_index', None)))
    status_report.append('\tPartition offset: {0!s}'.format(
        getattr(path_spec, 'start_offset', None)))
    return status_report

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
    path_specs = source_analyzer.ScanSource(evidence.local_path)

    status_report = ['Found {0:d} partition(s) in [{1:s}]:'.format(
        len(path_specs), evidence.local_path)]

    try:
      for path_spec in path_specs:
        status_report.extend(self._ProcessPartition(path_spec))
        partition_evidence = RawDiskPartition(source_path=evidence.local_path,
            path_spec=path_spec)
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
