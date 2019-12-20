# -*- coding: utf-8 -*- Copyright 2015 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at 
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.
"""Task ."""

from __future__ import unicode_literals

import os

from turbinia import config
from turbinia.evidence import ExportedFileArtifact
from turbinia.workers import TurbiniaTask


class FileArtifactExtractionTask(TurbiniaTask):
  """Task to run image_export (log2timeline)."""


  def __init__(self, artifact_name='artifact_name', *args, **kwargs):
    super(FileArtifactExtractionTask, self).__init__(*args, **kwargs)
    self.artifact_name = artifact_name

  def run(self, evidence, result):
    """Extracts artifacts using Plaso image_export.py.

    Args:
        evidence (Evidence object):  The evidence we will process.
        result (TurbiniaTaskResult): The object to place task results into.

    Returns:
        TurbiniaTaskResult object.
    """
    export_directory = os.path.join(self.output_dir, 'export')
    image_export_log = os.path.join(self.output_dir, '{0:s}.log'.format(self.id))
   
    self.default_recipe = {
        'meta_params': {'command_string': 'image_export.py'},
        'params': {
          'logfile': image_export_log,
          'w': export_directory,
          'partitions': 'all',
          'artifact_filters': self.artifact_name
        }
    }

    cmd = self.build_command()
    
    if config.DEBUG_TASKS:
      cmd.append('-d')
    cmd.append(evidence.local_path)


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
