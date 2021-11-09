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
"""Task for analysing Wordpress credentials."""

import os
import re
import subprocess
from turbinia import TurbiniaException

from turbinia.evidence import EvidenceState as state
from turbinia.evidence import ReportText
from turbinia.lib import text_formatter as fmt
from turbinia.lib.utils import bruteforce_password_hashes
from turbinia.lib.utils import extract_files
from turbinia.workers import Priority
from turbinia.workers import TurbiniaTask

_CREDS_REGEXP = r'(?P<username>.*)(?P<password>\$P\$.*)(?:\1)'
_WP_DB_NAME = 'wp_users.ibd'


class WordpressCredsAnalysisTask(TurbiniaTask):
  """Task to analyze the credentials of a Wordpress instance."""

  REQUIRED_STATES = [
      state.ATTACHED, state.CONTAINER_MOUNTED, state.DECOMPRESSED
  ]

  TASK_CONFIG = {
      # This is the length of time in seconds that the collected passwords will
      # be bruteforced.
      'bruteforce_timeout': 300
  }

  def run(self, evidence, result):
    """Run the Wordpress Creds worker.

    Args:
        evidence (Evidence object):  The evidence to process
        result (TurbiniaTaskResult): The object to place task results into.

    Returns:
        TurbiniaTaskResult object.
    """

    # Where to store the resulting output file.
    output_file_name = 'wordpress_creds_analysis.txt'
    output_file_path = os.path.join(self.output_dir, output_file_name)

    # What type of evidence we should output.
    output_evidence = ReportText(source_path=output_file_path)

    try:
      location, num_files = self._collect_wordpress_file(evidence)
      if num_files == 0:
        result.close(self, success=True, status='No Wordpress database found')
        return result
    except TurbiniaException as e:
      result.close(
          self, success=False,
          status='Error retrieving Wordpress database: {0:s}'.format(str(e)))
      return result

    try:
      (creds, hashnames) = self._extract_wordpress_hashes(location)
    except TurbiniaException as e:
      result.close(self, success=False, status=str(e))
      return result

    timeout = self.task_config.get('bruteforce_timeout')
    (report, priority, summary) = self._analyse_wordpress_creds(
        creds, hashnames, timeout=timeout)
    output_evidence.text_data = report
    result.report_data = report
    result.report_priority = priority

    # Write the report to the output file.
    with open(output_file_path, 'wb') as fh:
      fh.write(output_evidence.text_data.encode('utf8'))
      fh.write('\n'.encode('utf8'))

    # Add the resulting evidence to the result object.
    result.add_evidence(output_evidence, evidence.config)
    result.close(self, success=True, status=summary)

    return result

  def _collect_wordpress_file(self, evidence):
    """Extract artifacts using image_export.

    Args:
        evidence (Evidence object):  The evidence to process
    Returns:
        location (str): The file path to the extracted evidence.
        number of artifacts (int): The number of files extracted.
    """
    try:
      collected_artifacts = extract_files(
          file_name=_WP_DB_NAME,
          disk_path=evidence.local_path, output_dir=os.path.join(
              self.output_dir, 'artifacts'), credentials=evidence.credentials)
    except TurbiniaException as e:
      raise TurbiniaException(
          'artifact extraction failed: {0:s}'.format(str(e)))

    # Extract base dir from our list of collected artifacts
    location = os.path.dirname(collected_artifacts[0])

    return (location, len(collected_artifacts))

  def _extract_wordpress_hashes(self, location):
    """Dump the Wordpress credentials from a raw database file.

    Args:
        location (list): Directory of files extracted from the disk.

    Returns:
        creds (list): List of strings containing raw extracted credentials
        hashnames (dict): Dict mapping hash back to username for convenience.

    Raises:
      TurbiniaException: when the process fails.
    """
    creds = []
    hashnames = {}
    for dirs, _, files in os.walk(location):
      if _WP_DB_NAME in files:
        try:
          strings = subprocess.Popen(
              ['strings', os.path.join(dirs, _WP_DB_NAME)],
              stdout=subprocess.PIPE, text=True)
          grep = subprocess.run(['grep', r'\$P\$'], stdin=strings.stdout,
                                check=False, text=True, capture_output=True)
          if grep.returncode == 1:
            raise TurbiniaException('No Wordpress credentials found')
          if grep.returncode == 2:
            raise TurbiniaException(
                'Error grepping file: {0:s}'.format(grep.stdout))
        except subprocess.CalledProcessError as e:
          raise TurbiniaException(
              'Unable to strings/grep file: {0:s}'.format(str(e)))

        for cred in grep.stdout.strip().split('\n'):
          m = re.match(_CREDS_REGEXP, cred)
          if not m:
            continue
          (username, passwdhash) = (m.group('username'), m.group('password'))
          creds.append('{0:s}:{1:s}'.format(username, passwdhash))
          hashnames[passwdhash] = username
    return (creds, hashnames)

  def _analyse_wordpress_creds(self, creds, hashnames, timeout=300):
    """Attempt to brute force extracted Wordpress credentials.

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

    # 1000 is "phpass"
    weak_passwords = bruteforce_password_hashes(
        creds, tmp_dir=self.tmp_dir, timeout=timeout,
        extra_args='--username -m 400')

    if weak_passwords:
      priority = Priority.CRITICAL
      summary = 'Wordpress analysis found {0:d} weak password(s)'.format(
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
