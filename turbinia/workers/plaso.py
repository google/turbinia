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
from turbinia.evidence import APFSEncryptedDisk
from turbinia.evidence import BitlockerDisk
from turbinia.evidence import PlasoFile
from turbinia.workers import TurbiniaTask


class PlasoTask(TurbiniaTask):
  """Task to run Plaso (log2timeline)."""

  def run(self, evidence, result):
    """Task that process data with Plaso.

    Args:
        evidence (Evidence object):  The evidence we will process.
        result (TurbiniaTaskResult): The object to place task results into.

    Returns:
        TurbiniaTaskResult object.
    """
    config.LoadConfig()
    plaso_evidence = PlasoFile()

    # TODO: Convert to using real recipes after
    # https://github.com/google/turbinia/pull/486 is in.  For now we're just
    # using the --recipe_config flag, and this can be used with colon separated
    # values like:
    # --recipe_config='artifact_filters=BrowserFoo:BrowserBar,parsers=foo:bar'
    if evidence.config and evidence.config.get('artifact_filters'):
      artifact_filters = evidence.config.get('artifact_filters')
      artifact_filters = artifact_filters.replace(':', ',')
    else:
      artifact_filters = None

    if evidence.config and evidence.config.get('parsers'):
      parsers = evidence.config.get('parsers')
      parsers = parsers.replace(':', ',')
    else:
      parsers = None

    if evidence.config and evidence.config.get('file_filters'):
      file_filters = evidence.config.get('file_filters')
      file_filter_file = os.path.join(self.tmp_dir, 'file_filter.txt')
      try:
        with open(file_filter_file, 'wb') as file_filter_fh:
          for filter_ in file_filters.split(':'):
            file_filter_fh.write(filter_.encode('utf-8') + b'\n')
      except IOError as exception:
        message = 'Cannot write to filter file {0:s}: {1!s}'.format(
            file_filter_file, exception)
        result.close(self, success=False, status=message)
        return result
    else:
      file_filters = None
      file_filter_file = None

    if evidence.config and evidence.config.get('vss'):
      vss = evidence.config.get('vss')
    else:
      vss = None

    # Write plaso file into tmp_dir because sqlite has issues with some shared
    # filesystems (e.g NFS).
    plaso_file = os.path.join(self.tmp_dir, '{0:s}.plaso'.format(self.id))
    plaso_evidence.local_path = plaso_file
    plaso_log = os.path.join(self.output_dir, '{0:s}.log'.format(self.id))

    # TODO(aarontp): Move these flags into a recipe
    cmd = (
        'log2timeline.py --status_view none --hashers all '
        '--partition all').split()
    if config.DEBUG_TASKS:
      cmd.append('-d')
    if artifact_filters:
      cmd.extend(['--artifact_filters', artifact_filters])
    if parsers:
      cmd.extend(['--parsers', parsers])
    if file_filters:
      cmd.extend(['--file_filter', file_filter_file])
    if vss:
      cmd.extend(['--vss_stores', vss])

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
    cmd.extend([plaso_file, evidence.local_path])

    result.log('Running plaso as [{0:s}]'.format(' '.join(cmd)))

    self.execute(
        cmd, result, log_files=[plaso_log], new_evidence=[plaso_evidence],
        close=True)

    return result
