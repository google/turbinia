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
from tempfile import NamedTemporaryFile

from turbinia import config
from turbinia.evidence import APFSEncryptedDisk
from turbinia.evidence import BitlockerDisk
from turbinia.evidence import EvidenceState as state
from turbinia.evidence import PlasoFile
from turbinia.workers import TurbiniaTask


class PlasoTask(TurbiniaTask):
  """Task to run Plaso (log2timeline)."""

  # Plaso requires the Disk to be attached, but doesn't require it be mounted.
  REQUIRED_STATUS = [
      state.ATTACHED, state.PARENT_ATTACHED, state.PARENT_MOUNTED,
      state.DECOMPRESSED
  ]

  task_config = {
      'status_view': 'none',
      'hashers': 'all',
      'partition': 'all',
      'vss_stores': 'all',
  }

  def build_plaso_command(self, base_command, conf):
    """ Tasked with building the command """
    # Base command could be potentially placed in global configuration
    cmd = [base_command]
    for k, v in conf.items():
      prepend = '-'
      if len(k) > 1:
        prepend = '--'
      if k == 'file_filter' or k == 'file-filter' or k == 'filter-file':
        file_path = self.draft_list_file('filter_file', v)
        cmd.extend(['-f', file_path])
      elif k == 'yara_rules':
        file_path = self.copy_to_temp_file(v)
        cmd.extend(['--yara_rules', file_path])
      elif isinstance(v, list):
        if v:
          cmd.extend([prepend + k, ','.join(v)])
      elif isinstance(v, bool):
        if v:
          cmd.append(prepend + k)
      elif isinstance(v, str):
        if v:
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
    plaso_file = os.path.join(self.tmp_dir, '{0:s}.plaso'.format(self.id))
    plaso_evidence = PlasoFile(source_path=plaso_file)
    plaso_log = os.path.join(self.output_dir, '{0:s}.log'.format(self.id))

    working_recipe = self.task_config
    if self.recipe:
      working_recipe = self.recipe

    cmd = self.build_plaso_command('log2timeline.py', working_recipe)

    # TODO(aarontp): Move these flags into a recipe
    if config.DEBUG_TASKS:
      cmd.append('-d')

    if isinstance(evidence, (APFSEncryptedDisk, BitlockerDisk)):
      if evidence.recovery_key:
        cmd.extend([
            '--credential', 'recovery_password:{0:s}'.format(
                evidence.recovery_key)
        ])
      elif evidence.password:
        cmd.extend(['--credential', 'password:{0:s}'.format(evidence.password)])
      else:
        result.close(
            self, False, 'No credentials were provided '
            'for a bitlocker disk.')
        return result

    cmd.extend(['--logfile', plaso_log])
    cmd.extend([plaso_file, evidence.source_path])
    result.log('Running plaso as [{0:s}]'.format(' '.join(cmd)))

    self.execute(
        cmd, result, log_files=[plaso_log], new_evidence=[plaso_evidence],
        close=True)

    return result
