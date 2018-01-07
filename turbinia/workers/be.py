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
"""Tasks for running Bulk extractor."""

import os
import subprocess

from turbinia.workers import TurbiniaTask
from turbinia.workers import TurbiniaTaskResult

PAGE_SIZE = 16777216


class BulkExtractorTask(TurbiniaTask):
  """Task to run bulk_extractor."""

  def run(self, evidence, out_path, offsets, job_id, **kwargs):
    """Task that process data with bulk_extractor.

    Args:
        evidence: Path to data to process.
        out_path: Path to temporary storage of results.
        offsets: Where in the data to process.
        job_id: Unique ID for this task.
    Returns:
        job_id: The job_id provided.
    """
    # TODO(aarontp): Fix all these methods to take evidence
    # TODO(aarontp): Standardize output path format
    out_path = '{0:s}/{1:s}/{2}_{3}'.format(
        out_path, job_id, offsets[0], offsets[1])
    if not os.path.exists(out_path):
      os.makedirs(out_path)
    cmd_output = subprocess.check_output([
        '/usr/local/bin/be_wrapper.sh', src_path, out_path, '{0}-{1}'.format(
            offsets[0], offsets[1]), job_id])
    return job_id


class BulkExtractorCalcOffsetsTask(TurbiniaTask):
  """Task to calculate offsets for Bulk extractor."""

  def run(self, evidence, num_workers, page_size=PAGE_SIZE):
    """Reads data and calculates offsets based on page_size.

    Args:
      src_path: Path to image to be processed.
      num_workers: Number of workers that will be used in processing.
      page_size: Page size used in bulk_extractor.

    Returns:
      List of offsets.
    """
    disk_size = os.path.getsize(src_path)
    offset1 = 0
    offset2 = page_size
    parts = []
    offsets = []

    while offset1 < disk_size:
      parts.append((offset1, offset2))
      offset1 = offset2
      offset2 += page_size

    if num_workers > len(parts):
      parts_per_worker = 1
      num_workers = len(parts)
    else:
      parts_per_worker = len(parts) / num_workers

    extra = len(parts) % (parts_per_worker * num_workers)
    if extra:
      num_workers -= 1

    for i in range(num_workers):
      index_start = i * parts_per_worker
      index_stop = index_start + parts_per_worker
      instance_parts = parts[index_start:index_stop]
      o1 = instance_parts[0][0]
      o2 = instance_parts[-1][1]
      offsets.append(
          (o1, o2),)

    if extra:
      last_instance_parts = parts[index_stop:]
      o1 = last_instance_parts[0][0]
      o2 = last_instance_parts[-1][1]
      offsets.append(
          (o1, o2),)

    return offsets


class BulkExtractorReducerTask(TurbiniaTask):
  """Reduce bulk extractor outputs."""

  def run(self, evidence, results):
    """Task that reduces the results into one SQLite database.

    Args:
        results: List of returned values from tasks.

    Returns:
        Task result object (instance of TurbiniaTaskResult) as JSON.
    """
    job_id = results[0]
    cmd_output = subprocess.check_output([
        '/usr/local/bin/be_reducer.sh', job_id])
    result = TurbiniaTaskResult()
    result.add_result(result_type='PATH', result=cmd_output)
    return result
