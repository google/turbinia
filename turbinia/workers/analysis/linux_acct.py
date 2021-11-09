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
"""Task for analysing Linux account passwords."""

import os

from turbinia import TurbiniaException

from turbinia.evidence import EvidenceState as state
from turbinia.evidence import ReportText
from turbinia.lib import text_formatter as fmt
from turbinia.lib.utils import bruteforce_password_hashes
from turbinia.lib.utils import extract_artifacts
from turbinia.workers import Priority
from turbinia.workers import TurbiniaTask


class LinuxAccountAnalysisTask(TurbiniaTask):
  """Task to analyze a Linux password file."""

  REQUIRED_STATES = [
      state.ATTACHED, state.CONTAINER_MOUNTED, state.DECOMPRESSED
  ]

  TASK_CONFIG = {
      # This is the length of time in seconds that the collected passwords will
      # be bruteforced.
      'bruteforce_timeout': 300
  }

  def run(self, evidence, result):
    """Run the Linux Account worker.

    Args:
        evidence (Evidence object):  The evidence to process
        result (TurbiniaTaskResult): The object to place task results into.
    Returns:
        TurbiniaTaskResult object.
    """
    # Where to store the resulting output file.
    output_file_name = 'linux_account_analysis.txt'
    output_file_path = os.path.join(self.output_dir, output_file_name)

    # What type of evidence we should output.
    output_evidence = ReportText(source_path=output_file_path)

    try:
      collected_artifacts = extract_artifacts(
          artifact_names=['LoginPolicyConfiguration'],
          disk_path=evidence.local_path, output_dir=self.output_dir,
          credentials=evidence.credentials)
    except TurbiniaException as e:
      result.close(self, success=False, status=str(e))
      return result

    for filepath in collected_artifacts:
      if not filepath.endswith('shadow'):
        continue

      shadow_file = []
      # Read the input file
      with open(filepath, 'r') as input_file:
        shadow_file = input_file.readlines()

      hashnames = self._extract_linux_credentials(shadow_file)
      timeout = self.task_config.get('bruteforce_timeout')
      (report, priority, summary) = self.analyse_shadow_file(
          shadow_file, hashnames, timeout=timeout)
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
    result.close(self, success=True, status='No shadow files found')
    return result

  @staticmethod
  def _extract_linux_credentials(shadow):
    """Extract credentials from a Linux shadow files.

    Args:
      shadow (list): shadow file contents (list of str).

    Returns:
      dict: of hash against username.
    """
    hashnames = {}
    for line in shadow:
      (username, passwdhash, _) = line.split(':', maxsplit=2)
      hashnames[passwdhash] = username
    return hashnames

  def analyse_shadow_file(self, shadow, hashes, timeout=300):
    """Analyses a Linux shadow file.

    Args:
      shadow (list): shadow file content (list of str).
      hashes (dict): dict of hashes to usernames
      timeout (int): Time in seconds to run password bruteforcing.

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

    # 1800 is "sha512crypt $6$, SHA512 (Unix)"
    weak_passwords = bruteforce_password_hashes(
        shadow, tmp_dir=self.tmp_dir, timeout=timeout, extra_args='-m 1800')

    if weak_passwords:
      priority = Priority.CRITICAL
      summary = 'Shadow file analysis found {0:n} weak password(s)'.format(
          len(weak_passwords))
      report.insert(0, fmt.heading4(fmt.bold(summary)))
      line = '{0:n} weak password(s) found:'.format(len(weak_passwords))
      report.append(fmt.bullet(fmt.bold(line)))
      for password_hash, plaintext in weak_passwords:
        line = """User '{0:s}' with password '{1:s}'""".format(
            hashes[password_hash], plaintext)
        report.append(fmt.bullet(line, level=2))
    report = '\n'.join(report)
    return (report, priority, summary)
