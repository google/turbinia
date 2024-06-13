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

import os

from turbinia import config
from turbinia import evidence as evidence_module
from turbinia.evidence import EvidenceState as state
from turbinia.workers import TurbiniaTask


class FileArtifactExtractionTask(TurbiniaTask):
  """Task to run image_export (log2timeline)."""

  REQUIRED_STATES = [state.ATTACHED, state.CONTAINER_MOUNTED]

  def __init__(
      self, artifact_name=None, artifact_names=None, llm_artifacts=False):
    """Initialize the FileArtifactExtractionTask.

    Args:
      artifact_name (str): The name of the artifact to extract.
      artifact_names (List[str]): The names of the artifacts to extract.
      llm_artifacts (bool): Whether the artifact is for LLM analyzer.
    """
    super(FileArtifactExtractionTask, self).__init__()
    self.artifact_names = [artifact_name] if artifact_name else []
    if artifact_names:
      self.artifact_names.extend(artifact_names)
    self.job_name = "FileArtifactExtractionJob"
    self.llm_artifacts = llm_artifacts

  def run(self, evidence, result):
    """Extracts artifacts using Plaso image_export.

    Args:
        evidence (Evidence object):  The evidence we will process.
        result (TurbiniaTaskResult): The object to place task results into.

    Returns:
        TurbiniaTaskResult object.
    """
    config.LoadConfig()

    if not self.artifact_names:
      result.log('Tried to run image_export without no artifacts!')
      result.close(
          self,
          False,
          'image_export failed for artifacts {0:s} - artifact_name or'
          ' artifact_names not provided.'.format(self.artifact_names),
      )
      return result
    if not evidence.local_path:
      result.log('Tried to run image_export without local_path')
      result.close(
          self,
          False,
          'image_export failed for artifacts {0:s} - local_path not'
          ' provided.'.format(self.artifact_names),
      )
      return result
    export_directory = os.path.join(self.output_dir, 'export')
    image_export_log = os.path.join(self.output_dir, f'{self.id:s}.log')

    err_cnt = 0
    extracted_artifacts_cnt = 0
    extracted_artifacts_filenames = []
    # This will make sure we don't add the same evidence multiple times when we
    # re-walk export directory with each artifact. It will also de-dupe files
    # exported by multiple artifacts, i.e. RedisConfigurationFile and
    # RedisConfigFile will both grab /etc/redis/redis.conf on a linux host.
    already_added_paths = []
    # We won't process all artifacts in a single image_exporter
    # execution as there is no way to tie back an output file to
    # an input artifact_name.
    for artifact_name in self.artifact_names:
      artifact_filenames = []
      cmd = self.create_image_export_cmd(
          artifact_name, evidence, export_directory, image_export_log)
      result.log(f"Running image_export as [{' '.join(cmd):s}]")

      ret, _ = self.execute(cmd, result, log_files=[image_export_log])
      if ret:
        result.log(f'image_export failed for artifact {artifact_name:s}.')
        err_cnt += 1

      # LLM analyzer uses a seperate version of ExportedFileArtifact to avoid
      # redundent processing of artifacts exported several times by LLM Analyzer
      # and other analyzers.
      artifact_type = getattr(evidence_module, 'ExportedFileArtifact')
      if self.llm_artifacts:
        artifact_type = getattr(evidence_module, 'ExportedFileArtifactLLM')

      for dirpath, _, filenames in os.walk(export_directory):
        for filename in filenames:
          abs_path = os.path.join(dirpath, filename)
          if abs_path not in already_added_paths:
            exported_artifact = artifact_type(
                artifact_name=artifact_name, source_path=abs_path)
            result.log(f'Adding artifact {filename:s}')
            result.add_evidence(exported_artifact, evidence.config)
            already_added_paths.append(abs_path)
            artifact_filenames.append(filename)

      if artifact_filenames:
        extracted_artifacts_cnt += 1
      extracted_artifacts_filenames.extend(artifact_filenames)

    if err_cnt == len(self.artifact_names):
      result.close(
          self, False,
          f'image_export failed for artifacts {self.artifact_names}.')
      return result

    result.close(
        self,
        True,
        f'Extracted files for {extracted_artifacts_cnt} out of'
        f' {len(self.artifact_names)} artifacts with {err_cnt} errors:'
        f' {extracted_artifacts_filenames}',
    )

    return result

  def create_image_export_cmd(
      self, artifact_name, evidence, export_directory, image_export_log):
    """Create the image_export command.

    Args:
      artifact_name (str): The name of the artifact to extract.
      evidence (Evidence object):  The evidence we will process.
      export_directory (str): The directory to export the artifacts to.
      image_export_log (str): The path to the image_export log file.

    Returns:
      List[str]: The image_export command.
    """

    cmd = [
        'image_export',
        '--no-hashes',
        '--logfile',
        image_export_log,
        '--write',
        export_directory,
        '--partitions',
        'all',
        '--volumes',
        'all',
        '--unattended',
        '--artifact_filters',
        artifact_name,
    ]

    if not config.DOCKER_ENABLED:
      cmd.insert(0, 'sudo')

    if config.DEBUG_TASKS or self.task_config.get('debug_tasks'):
      cmd.append('-d')

    if evidence.credentials:
      for credential_type, credential_data in evidence.credentials:
        cmd.extend(['--credential', f'{credential_type:s}:{credential_data:s}'])

    # Path to the source image/directory.
    cmd.append(evidence.local_path)
    return cmd
