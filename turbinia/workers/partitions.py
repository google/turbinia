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
from turbinia.lib.dfvfs import SourceAnalyzer
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
    volumes = source_analyzer.Analyze(evidence.local_path)

    try:
      for identifier, volume in volumes.items():
        partition_evidence = RawDiskPartition(
            source_path=evidence.local_path,
            volume_identifier=identifier,
            volume_type=volume['description'],
            offset=volume['offset'],
            size=volume['size'])
        result.add_evidence(partition_evidence, evidence.config)
      status_report = 'Found {0:d} partition(s) in [{1:s}]'.format(
          len(volumes), evidence.local_path)
      success = True
    except TurbiniaException as e:
      status_report = 'Error enumerating Docker containers: {0!s}'.format(e)

    result.log('Scanning of [{0:s}] is complete'.format(evidence.local_path))

    result.report_priority = Priority.LOW
    result.report_data = status_report
    result.close(self, success=success, status=status_report)

    return result
