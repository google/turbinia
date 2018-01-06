# -*- coding: utf-8 -*-
# Copyright 2015 Google Inc.
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
"""Job to execute bulk_extractor task."""

from turbinia.jobs import TurbiniaJob
from turbinia.workers.be import BulkExtractorCalcOffsetsTask
from turbinia.workers.be import BulkExtractorReducerTask
from turbinia.workers.be import BulkExtractorTask


class BulkExtractorPreprocessJob(TurbiniaJob):

  evidence_input = []
  evidence_output = []

  def create_tasks(self, evidence, out_path, workers=1):
    """Create task for bulk_extractor.

    Args:
        src_path: Path to the data to process.
        out_path: Path to where to put the result.
        workers: Number of workers to run the Job on.
    Returns:
        A list of TurbiniaTasks.
    """
    # TODO(aarontp): Fix up this method.  Refactor out method args into config
    # or options.
    self.tasks.append(BulkExtractorCalcOffsetsTask(evidence))
    return self.tasks


class BulkExtractorJob(TurbiniaJob):

  evidence_input = []
  evidence_output = []

  def create_tasks(self, evidence):
    """Create task for bulk_extractor.

    Args:
      Evidence object to process

    Returns:
        A list of BulkExtractorTasks.
    """
    # TODO(aarontp): Put offset into evidence type for this job
    self.tasks.extend([BulkExtractorTask(e) for e in evidence])
    return self.tasks
