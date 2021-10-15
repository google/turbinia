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
"""Task to extract binary files from an evidence object provided."""

from __future__ import unicode_literals

import logging
import json
import os
import textwrap

from turbinia import TurbiniaException
from turbinia import config
from turbinia.evidence import EvidenceState as state
from turbinia.workers import TurbiniaTask
from turbinia.evidence import BinaryExtraction


class BinaryExtractorTask(TurbiniaTask):
  """Extract binaries out of evidence and provide JSON file with hashes.

  Attributes:
    json_path(str): path to output JSON file.
    binary_extraction_dir(str): path to extraction directory.
  """

  REQUIRED_STATES = [state.ATTACHED]

  TASK_CONFIG = {
      # This is an arbitrary path that will be put into a custom artifact
      # definition so that the files at this path are extracted.  See the path
      # specification format in the ForensicArtifacts documentation:
      # https://artifacts.readthedocs.io/en/latest/sources/Format-specification.html
      'binary_extraction_path': None
  }

  def __init__(self, *args, **kwargs):
    """Initializes BinaryExtractorTask."""
    super(BinaryExtractorTask, self).__init__(*args, **kwargs)
    self.json_path = None
    self.binary_extraction_dir = None

  def check_extraction(self):
    """Checks counts for extracted binaries and hashes.

    Returns:
      Tuple(
        binary_cnt(int): Number of extracted binaries.
        hash_cnt(int): Number of extracted hashes.
      )
    """

    # Check if hashes.json file was generated.
    if not os.path.exists(self.json_path):
      raise TurbiniaException(
          'The file {0:s} was not found. Please ensure you '
          'have Plaso version 20191203 or greater deployed'.format(
              self.json_path))

    with open(self.json_path) as json_file:
      hashes = json.load(json_file)

    binary_cnt = sum(
        len(files) for _, _, files in os.walk(self.binary_extraction_dir)) - 1
    hash_cnt = len(hashes)

    return (binary_cnt, hash_cnt)

  def run(self, evidence, result):
    """Task that extracts binaries with image_export.py.

    Args:
        evidence (Evidence object):  The evidence we will process.
        result (TurbiniaTaskResult): The object to place task results into.

    Returns:
        TurbiniaTaskResult object.
    """

    config.LoadConfig()
    binary_extraction_evidence = BinaryExtraction()

    binary_extraction_evidence.local_path = self.output_dir
    binary_extraction_evidence.uncompressed_directory = self.output_dir
    image_export_log = os.path.join(self.output_dir, 'binary_extraction.log')
    self.binary_extraction_dir = os.path.join(
        self.output_dir, 'extracted_binaries')
    self.json_path = os.path.join(self.binary_extraction_dir, 'hashes.json')

    cmd = [
        'image_export.py', '--partitions', 'all', '--volumes', 'all',
        '--no_vss', '--unattended', '--logfile', image_export_log
    ]

    if self.task_config.get('binary_extraction_path'):
      artifact_dir = os.path.join(self.tmp_dir, 'artifacts')
      artifact_file = os.path.join(artifact_dir, 'artifacts.yaml')
      os.mkdir(artifact_dir)
      binary_extraction_path = self.task_config.get('binary_extraction_path')
      result.log(
          'Using custom artifact path {0:s}'.format(binary_extraction_path))

      artifact_text = textwrap.dedent(
          """
          name: TurbiniaCustomArtifact
          doc: Ad hoc artifact created for file extraction.
          sources:
          - type: FILE
            attributes:
                paths: ['{0:s}']
          """)
      artifact_text = artifact_text.format(binary_extraction_path)

      with open(artifact_file, 'wb') as artifact:
        artifact.write(artifact_text.encode('utf-8'))
      cmd.extend([
          '--custom_artifact_definitions', artifact_file, '--artifact_filters',
          'TurbiniaCustomArtifact'
      ])
    else:
      cmd.extend(['--signatures', 'elf,exe_mz'])

    if evidence.credentials:
      for credential_type, credential_data in evidence.credentials:
        cmd.extend([
            '--credential', '{0:s}:{1:s}'.format(
                credential_type, credential_data)
        ])

    if config.DEBUG_TASKS or self.task_config.get('debug_tasks'):
      cmd.append('-d')
    cmd.extend(['-w', self.binary_extraction_dir, evidence.local_path])

    result.log('Running image_export as [{0:s}]'.format(' '.join(cmd)))
    self.execute(
        cmd, result, log_files=[image_export_log, self.json_path],
        new_evidence=[binary_extraction_evidence])

    try:
      binary_cnt, hash_cnt = self.check_extraction()
    except TurbiniaException as exception:
      message = 'File extraction failed: {0!s}'.format(exception)
      result.close(self, success=False, status=message)
      return result

    status = (
        'Extracted {0:d} hashes and {1:d} files from the '
        'evidence.'.format(hash_cnt, binary_cnt))

    if hash_cnt != binary_cnt:
      result.log(
          'Number of extracted binaries is not equal to the number '
          'of extracted hashes. This might indicate issues with '
          'image_export.py. Check binary_extraction.log for more '
          'details.', logging.WARNING)

    binary_extraction_evidence.compress()
    result.close(self, success=True, status=status)

    return result
