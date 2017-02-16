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
"""Job to execute Plaso task."""

import uuid

from turbinia.jobs import TurbiniaJob
from turbinia.workers.plaso import PlasoTask

from tubinia.artifact import RawDisk, GoogleCloudDisk, PlasoFile


class PlasoJob(TurbiniaJob):

  # The types of artifacts that this Job will process
  artifact_input = [type(RawDisk()), type(GoogleCloudDisk())]
  artifact_output = [type(PlasoFile())]

  def create_task(self, src_path, out_path, job_id=None, workers=1):
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
    task = PlasoTask().delay(src_path, out_path, job_id, workers=workers)
    return task, job_id

  def __init__(self):
    super(PlasoJob, self).__init__(name='PlasoJob')

  def cli(self, cmd_args):
    """Run Plaso job from the command line.

    Args:
        cmd_args: Arguments from argparse (instance of argparse.Namespace).
    """
    task, job_id = self.create_task(
        src_path=cmd_args.source, out_path=cmd_args.output)
    self.run_cli(task, job_id)
