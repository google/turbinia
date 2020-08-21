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

from turbinia.lib.dfvfs import SourceAnalyzer
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

    source_analyzer = SourceAnalyzer(auto_recurse=True)
    source_analyzer.Analyze(evidence.local_path, result)

    result.log('Scanning of [{0:s}] is complete'.format(evidence.local_path))

    return result
