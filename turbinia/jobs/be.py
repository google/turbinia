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

import uuid

from celery import group
from celery import chord

from turbinia.jobs import TurbiniaJob
from turbinia.workers.be import BulkExtractorTask
from turbinia.workers.be import BulkExtractorReducerTask
from turbinia.workers.be import BulkExtractorCalcOffsetsTask


class BulkExtractorJob(TurbiniaJob):

  @staticmethod
  def create_task(src_path, out_path, job_id=None, workers=1):
    """Create task for bulk_extractor.

    Args:
        src_path: Path to the data to process.
        out_path: Path to where to put the result.
        job_id: Unique identifier for the job (optional).
        workers: Number of workers to run the Job on.
    Returns:
        A Celery task (instance of celery.Task).
    """
    if not job_id:
      job_id = uuid.uuid4().hex
    offsets_task = BulkExtractorCalcOffsetsTask().delay(src_path, workers)
    offsets = offsets_task.get()
    task_group = group(BulkExtractorTask().s(src_path, out_path, offset, job_id)
                       for offset in offsets)
    task_chord = chord(task_group)(BulkExtractorReducerTask().s())
    return task_chord, job_id

  def cli(self, cmd_args):
    """Run bulk_extractor job from the command line.

    Args:
        cmd_args: Arguments from argparse (instance of argparse.Namespace).
    """
    task, job_id = self.create_task(
        src_path=cmd_args.source, out_path=cmd_args.output,
        workers=int(cmd_args.num_tasks))
    self.run_cli(task, job_id)
