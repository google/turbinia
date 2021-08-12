# -*- coding: utf-8 -*-
# Copyright 2021 Google Inc.
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
"""Task for analysing Windows account passwords."""

import os
import subprocess

from turbinia import TurbiniaException
from turbinia.evidence import EvidenceState as state
from turbinia.evidence import ReportText
from turbinia.lib import text_formatter as fmt
from turbinia.lib.utils import bruteforce_password_hashes
from turbinia.lib.utils import extract_artifacts
from turbinia.workers import Priority
from turbinia.workers import TurbiniaTask


class WindowsAccountAnalysisTask(TurbiniaTask):
  """Task to analyze a Linux password file."""

  REQUIRED_STATES = [state.ATTACHED, state.DECOMPRESSED]

  def run(self, evidence, result):
    """Run the Windows Account worker.

    Args:
        evidence (Evidence object):  The evidence to process
        result (TurbiniaTaskResult): The object to place task results into.
    Returns:
        TurbiniaTaskResult object.
    """
    # Where to store the resulting output file.
    output_file_name = 'windows_account_analysis.txt'
    output_file_path = os.path.join(self.output_dir, output_file_name)

    # What type of evidence we should output.
    output_evidence = ReportText(source_path=output_file_path)

    try:
      location = self._collect_windows_files(evidence)
    except TurbiniaException as e:
      result.close(
          self, success=True,
          status='No Windows account files found: {0:s}'.format(str(e)))
      return result
    (creds, hashnames) = self._extract_windows_hashes(
        os.path.join(location, 'Windows', 'System32', 'config'))
    (report, priority, summary) = self._analyse_windows_creds(creds, hashnames)
    output_evidence.text_data = report
    result.report_priority = priority
    result.report_data = report

    # Write the report to the output file.
    with open(output_file_path, 'wb') as fh:
      fh.write(output_evidence.text_data.encode('utf-8'))

    # Add the resulting evidence to the result object.
    result.add_evidence(output_evidence, evidence.config)
    result.close(self, success=True, status=summary)
    return result

  def _collect_windows_files(self, evidence):
    try:
      collected_artifacts = extract_artifacts(
          artifact_names=['WindowsSystemRegistryFiles'],
          disk_path=evidence.local_path, output_dir=self.output_dir)
    except TurbiniaException as e:
      raise TurbiniaException('artifact extraction failed: {}'.format(str(e)))

    # Extract base dir from our list of collected artifacts
    location = os.path.dirname(collected_artifacts[0])

    return location

  def _extract_windows_hashes(self, location):
    # Dump the secrets into a file

    IGNORE_CREDS = ['31d6cfe0d16ae931b73c59d7e0c089c0']

    hash_file = '/tmp/windows_hashes'
    cmd = [
        '/opt/impacket-env/bin/python', '/usr/bin/secretsdump.py', '-system',
        location + '/SYSTEM', '-sam', location + '/SAM', '-hashes',
        'lmhash:nthash', 'LOCAL', '-outputfile', hash_file
    ]

    with open(os.devnull, 'w') as devnull:
      try:
        child = subprocess.Popen(cmd, stdout=devnull, stderr=devnull)
        child.communicate()
      except OSError as e:
        raise TurbiniaException('impacket failed: {0:s}'.format(str(e)))

    creds = []
    hashnames = {}
    hash_file = hash_file + '.sam'
    if os.path.isfile(hash_file):
      with open(hash_file, 'r') as fh:
        for line in fh:
          (username, _, _, passwdhash, _, _, _) = line.split(':')
          if passwdhash in IGNORE_CREDS:
            continue
          creds.append(line.strip())
          hashnames[passwdhash] = username
      os.remove(hash_file)
    return (creds, hashnames)

  def _analyse_windows_creds(self, creds, hashnames, timeout=300):
    report = []
    summary = 'No weak passwords found'
    priority = Priority.LOW
    weak_passwords = bruteforce_password_hashes(
        creds, tmp_dir=self.tmp_dir, timeout=timeout, extra_args='-m 1000')
    if weak_passwords:
      priority = Priority.CRITICAL
      summary = 'Registry analysis found {0:d} weak password(s)'.format(
          len(weak_passwords))
      report.insert(0, fmt.heading4(fmt.bold(summary)))
      line = '{0:n} weak password(s) found:'.format(len(weak_passwords))
      report.append(fmt.bullet(fmt.bold(line)))
      for password_hash, plaintext in weak_passwords:
        if password_hash in hashnames:
          line = """User '{0:s}' with password '{1:s}'""".format(
              hashnames[password_hash], plaintext)
          report.append(fmt.bullet(line, level=2))
    report = '\n'.join(report)
    return (report, priority, summary)
