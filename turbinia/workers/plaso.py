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
import logging

from turbinia import config
from turbinia.evidence import EvidenceState as state
from turbinia.evidence import PlasoFile
from turbinia.workers import TurbiniaTask
from turbinia.lib import file_helpers


class PlasoTask(TurbiniaTask):
  """Parent task for PlasoJob sub-tasks."""

  # Plaso requires the Disk to be attached, but doesn't require it be mounted.
  REQUIRED_STATES = [
      state.ATTACHED, state.DECOMPRESSED, state.CONTAINER_MOUNTED
  ]

  def test_yara_rules(self, file_path, result):
    """Test the given Yara rules for syntactical validity before processing.

    Args:
      file_path (str): Location on disk of the Yara rules to be tested.
      result (TurbiniaTaskResult): The object to place task results into.
    
    Returns:
      True if rules are good, else False
    """
    cmd = ['/opt/fraken/fraken', '-rules', file_path, '-testrules']
    (ret, _) = self.execute(cmd, result)
    if ret == 0:
      return True
    return False

  def build_plaso_command(self, base_command, conf):
    """Builds a typical plaso command, contains logic specific to log2timeline.

    Args:
      base_command (str): Command to invoke log2timeline (e.g. log2timeline)
      conf (dict): Dynamic config containing the parameters for the command.

    Returns:
      String for valid Log2timeline command.
    """
    self.result.log(
        f'Generating Plaso command line from arguments: {conf!s}',
        level=logging.DEBUG)
    cmd = [base_command]
    for k, v in conf.items():
      cli_args = [
          'status_view', 'hashers', 'hasher_file_size_limit', 'partitions',
          'vss_stores', 'custom_artifact_definitions', 'parsers',
          'artifact_filters', 'file_filter', 'yara_rules', 'volumes'
      ]
      if (k not in cli_args or not v):
        continue
      prepend = '-'
      if len(k) > 1:
        prepend = '--'
      if k == 'file_filter':
        file_path = file_helpers.write_list_to_temp_file(
            v, preferred_dir=self.tmp_dir)
        cmd.extend(['-f', file_path])
      elif k == 'yara_rules':
        file_path = file_helpers.write_str_to_temp_file(
            v, preferred_dir=self.tmp_dir)
        rules_check = self.test_yara_rules(file_path, self.result)
        if rules_check:
          cmd.extend(['--yara_rules', file_path])
      elif isinstance(v, list):
        cmd.extend([prepend + k, ','.join(v)])
      elif isinstance(v, bool):
        cmd.append(prepend + k)
      elif isinstance(v, str):
        cmd.extend([prepend + k, v])
    return cmd

  def run(self, evidence, result):
    """Task that process data with Plaso.

    Args:
        evidence (Evidence object):  The evidence we will process.
        result (TurbiniaTaskResult): The object to place task results into.

    Returns:
        TurbiniaTaskResult object.
    """

    config.LoadConfig()

    # Write plaso file into tmp_dir because sqlite has issues with some shared
    # filesystems (e.g NFS).
    plaso_file = os.path.join(self.tmp_dir, f'{self.id:s}.plaso')
    plaso_evidence = PlasoFile(source_path=plaso_file)
    plaso_log = os.path.join(self.output_dir, f'{self.id:s}.log')

    cmd = self.build_plaso_command('log2timeline', self.task_config)

    if config.DEBUG_TASKS or self.task_config.get('debug_tasks'):
      cmd.append('-d')

    if evidence.credentials:
      for credential_type, credential_data in evidence.credentials:
        cmd.extend(['--credential', f'{credential_type:s}:{credential_data:s}'])

    cmd.extend(['--temporary_directory', self.tmp_dir])
    cmd.extend(['--logfile', plaso_log])
    cmd.extend(['--unattended'])
    cmd.extend(['--storage_file', plaso_file])
    cmd.extend([evidence.local_path])

    result.log(f"Running {self.name:s} as [{' '.join(cmd):s}]")
    self.execute(
        cmd, result, log_files=[plaso_log], new_evidence=[plaso_evidence],
        close=True)

    return result


class PlasoParserTask(PlasoTask):
  """Task to run Plaso parsers (log2timeline)."""

  TASK_CONFIG = {
      # 'none' as indicated in the options for status_view within
      # the Plaso documentation
      'status_view': 'none',
      'hashers': 'none',
      'hasher_file_size_limit': None,
      'partitions': 'all',
      'volumes': 'all',
      'vss_stores': 'none',
      # artifact_filters and file_filter are mutually exclusive
      # parameters and Plaso will error out if both parameters are used.
      'artifact_filters': None,
      'file_filter': None,
      'custom_artifact_definitions': None,
      # Disable filestat parser. PlasoHasherTask will run it separately.
      'parsers': '!filestat',
      'yara_rules': None
  }


class PlasoHasherTask(PlasoTask):
  """Task to run Plaso hashers. This task only runs the filestat parser."""

  TASK_CONFIG = {
      # 'none' as indicated in the options for status_view within
      # the Plaso documentation
      'status_view': 'none',
      'hashers': 'all',
      'hasher_file_size_limit': '1073741824',
      'partitions': 'all',
      'volumes': 'all',
      'vss_stores': 'none',
      # artifact_filters and file_filter are mutually exclusive
      # parameters and Plaso will error out if both parameters are used.
      'artifact_filters': None,
      'file_filter': None,
      'custom_artifact_definitions': None,
      'parsers': 'filestat',
      'yara_rules': None
  }
