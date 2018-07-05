# -*- coding: utf-8 -*-
# Copyright 2018 Google Inc.
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
"""Job to execute strings task."""

from turbinia.evidence import GoogleCloudDisk
from turbinia.evidence import GoogleCloudDiskRawEmbedded
from turbinia.evidence import RawDisk
from turbinia.evidence import TextFile
from turbinia.jobs import TurbiniaJob
from turbinia.workers.strings import StringsAsciiTask
from turbinia.workers.strings import StringsUnicodeTask


class StringsJob(TurbiniaJob):
  """Strings collection Job.

  This will generate a Unicode and ASCII string collection task for each piece
  of evidence.
  """

  # The types of evidence that this Job will process
  evidence_input = [type(RawDisk()), type(GoogleCloudDisk()),
                    type(GoogleCloudDiskRawEmbedded())]
  evidence_output = [type(TextFile())]

  def __init__(self):
    super(StringsJob, self).__init__(name='StringsJob')

  def create_tasks(self, evidence):
    """Create task for Strings.

    Args:
      evidence: List of evidence object to process

    Returns:
        A list of tasks to schedule.
    """
    # Generate tasks for both types of Strings jobs
    tasks = [StringsAsciiTask() for _ in evidence]
    tasks.extend([StringsUnicodeTask() for _ in evidence])
    return tasks
