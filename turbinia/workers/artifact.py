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
"""Task for running Plaso."""

from __future__ import unicode_literals

import os

from turbinia import config
from turbinia.evidence import ExportedFileArtifact
from turbinia.evidence import EvidenceState as state
from turbinia.workers import TurbiniaTask


class FileArtifactExtractionTask(TurbiniaTask):
  """Task to run image_export (log2timeline)."""

  REQUIRED_STATES = [state.ATTACHED]

  def __init__(self, artifact_name='FileArtifact'):
    super(FileArtifactExtractionTask, self).__init__()
    self.artifact_name = artifact_name

  def run(self, evidence, result):
    """Extracts artifacts using Plaso image_export.py.

    Args:
        evidence (Evidence object):  The evidence we will process.
        result (TurbiniaTaskResult): The object to place task results into.

    Returns:
        TurbiniaTaskResult object.
    """
    config.LoadConfig()

    export_directory = os.path.join(self.output_dir, 'export')
    image_export_log = os.path.join(
        self.output_dir, '{0:s}.log'.format(self.id))

    cmd = [
        'sudo',
        'image_export.py',
        '--no-hashes',
        '--logfile',
        image_export_log,
        '-w',
        export_directory,
        '--partitions',
        'all',
        '--volumes',
        'all',
        '--unattended',
        '--artifact_filters',
        self.artifact_name,
    ]
    if config.DEBUG_TASKS or self.task_config.get('debug_tasks'):
      cmd.append('-d')

    if evidence.credentials:
      for credential_type, credential_data in evidence.credentials:
        cmd.extend([
            '--credential', '{0:s}:{1:s}'.format(
                credential_type, credential_data)
        ])

    # Path to the source image/directory.
    cmd.append(evidence.local_path)
    if not evidence.local_path:
      result.log('Tried to run image_export without local_path')
      result.close(
          self, False,
          'image_export.py failed for artifact {0:s} - local_path not provided.'
          .format(self.artifact_name))
      return result

    result.log('Running image_export as [{0:s}]'.format(' '.join(cmd)))

    ret, _ = self.execute(cmd, result, log_files=[image_export_log])
    if ret:
      result.close(
          self, False, 'image_export.py failed for artifact {0:s}.'.format(
              self.artifact_name))
      return result

    for dirpath, _, filenames in os.walk(export_directory):
      for filename in filenames:
        exported_artifact = ExportedFileArtifact(
            artifact_name=self.artifact_name, source_path=os.path.join(
                dirpath, filename))
        result.log('Adding artifact {0:s}'.format(filename))
        result.add_evidence(exported_artifact, evidence.config)

    result.close(
        self, True, 'Extracted {0:d} new {1:s} artifacts'.format(
            len(result.evidence), self.artifact_name))

    return result
