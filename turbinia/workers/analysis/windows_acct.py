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

from turbinia import TurbiniaException
from turbinia.evidence import EvidenceState as state
from turbinia.evidence import ReportText
from turbinia.lib import text_formatter as fmt
from turbinia.lib.utils import bruteforce_password_hashes
from turbinia.lib.utils import extract_artifacts
from turbinia.workers import Priority
from turbinia.workers import TurbiniaTask


class WindowsAccountAnalysisTask(TurbiniaTask):
  """Task to analyze Windows accounts."""

  REQUIRED_STATES = [
      state.ATTACHED, state.CONTAINER_MOUNTED, state.DECOMPRESSED
  ]

  TASK_CONFIG = {
      # This is the length of time in seconds that the collected passwords will
      # be bruteforced.
      'bruteforce_timeout': 300
  }

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
      (location, num_files) = self._collect_windows_files(evidence)
    except TurbiniaException as e:
      result.close(
          self, success=True,
          status='No Windows account files found: {0:s}'.format(str(e)))
      return result
    if num_files < 2:
      result.close(self, success=True, status='No Windows account files found')
      return result
    try:
      (creds, hashnames) = self._extract_windows_hashes(
          result, os.path.join(location, 'Windows', 'System32', 'config'))
    except TurbiniaException as e:
      result.close(
          self, success=False,
          status='Unable to extract hashes from registry files: {0:s}'.format(
              str(e)))
      return result
    timeout = self.task_config.get('bruteforce_timeout')
    (report, priority, summary) = self._analyse_windows_creds(
        creds, hashnames, timeout=timeout)
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
    """Extract artifacts using image_export.

    Args:
        evidence (Evidence object):  The evidence to process
    Returns:
        location (str): The file path to the extracted evidence.
        number of artifacts (int): The number of files extracted.
    """
    try:
      collected_artifacts = extract_artifacts(
          artifact_names=['WindowsSystemRegistryFiles'],
          disk_path=evidence.local_path, output_dir=self.output_dir,
          credentials=evidence.credentials)
    except TurbiniaException as e:
      raise TurbiniaException('artifact extraction failed: {}'.format(str(e)))

    # Extract base dir from our list of collected artifacts
    location = os.path.dirname(collected_artifacts[0])

    return (location, len(collected_artifacts))

  def _extract_windows_hashes(self, result, location):
    """Dump the secrets from the Windows registry files.

    Args:
        result (TurbiniaTaskResult): The object to place task results into.
        location (str): File path to the extracted registry files.

    Returns:
        creds (list): List of strings containing raw extracted credentials
        hashnames (dict): Dict mapping hash back to username for convenience.
    """

    # Default (empty) hash
    IGNORE_CREDS = ['31d6cfe0d16ae931b73c59d7e0c089c0']

    hash_file = os.path.join(self.tmp_dir, 'windows_hashes')
    cmd = [
        'secretsdump.py', '-system', location + '/SYSTEM', '-sam',
        location + '/SAM', '-hashes', 'lmhash:nthash', 'LOCAL', '-outputfile',
        hash_file
    ]

    impacket_log = os.path.join(self.output_dir, 'impacket.log')
    self.execute(cmd, result, stdout_file=impacket_log)

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
    else:
      raise TurbiniaException('Extracted hash file not found.')

    return (creds, hashnames)

  def _analyse_windows_creds(self, creds, hashnames, timeout=300):
    """Attempt to brute force extracted Windows credentials.

    Args:
        creds (list): List of strings containing raw extracted credentials
        hashnames (dict): Dict mapping hash back to username for convenience.
        timeout (int): How long to spend cracking.

    Returns:
      Tuple(
        report_text(str): The report data
        report_priority(int): The priority of the report (0 - 100)
        summary(str): A summary of the report (used for task status)
      )
    """
    report = []
    summary = 'No weak passwords found'
    priority = Priority.LOW

    # 1000 is "NTLM"
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
