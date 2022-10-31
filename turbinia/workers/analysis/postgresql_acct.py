# -*- coding: utf-8 -*-
# Copyright 2022 Google Inc.
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
"""Task for analysing PostgreSQL account passwords."""

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

_CREDS_REGEXP = r'(?P<username>.*?)(?:\\xff)+I(?P<password>md5.{32})'
_PG_CONF_NAME = 'postgresql.conf'


class PostgresAccountAnalysisTask(TurbiniaTask):
  """Task to analyze Postgres credentials."""

  REQUIRED_STATES = [
      state.ATTACHED, state.MOUNTED, state.CONTAINER_MOUNTED, state.DECOMPRESSED
  ]

  TASK_CONFIG = {
      # This is the length of time in seconds that the collected passwords will
      # be bruteforced.
      'bruteforce_timeout': 300
  }

  def run(self, evidence, result):
    """Run the Postgres Account worker.

    Args:
        evidence (Evidence object):  The evidence to process
        result (TurbiniaTaskResult): The object to place task results into.
    Returns:
        TurbiniaTaskResult object.
    """
    # Where to store the resulting output file.
    output_file_name = 'postgres_account_analysis.txt'
    output_file_path = os.path.join(self.output_dir, output_file_name)

    # What type of evidence we should output.
    output_evidence = ReportText(source_path=output_file_path)

    # 1) Find postgresql.conf
    try:
      location, num_files = self._collect_conf_files(evidence)
      if num_files == 0:
        result.close(self, success=True, status='No PostgreSQL config found')
        return result
    except TurbiniaException as exception:
      result.close(
          self, success=False,
          status='Error retrieving PostgreSQL config: {0:s}'.format(
              str(exception)))
      return result
    # 2) Grep for data dirs
    try:
      data_dirs = self._extract_data_dir(location, result)
    except TurbiniaException as exception:
      result.close(self, success=False, status=str(exception))
      return result
    # 3) Extract creds
    try:
      hashnames = self._extract_creds(data_dirs, evidence)
    except TurbiniaException as exception:
      result.close(self, success=False, status=str(exception))
      return result

    # 4) Bruteforce
    timeout = self.task_config.get('bruteforce_timeout')
    (report, priority, summary) = self._analyse_postgres_creds(
        hashnames, timeout=timeout)
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

  def _collect_conf_files(self, evidence):
    """Extract artifacts using image_export.

    Args:
        evidence (Evidence object):  The evidence to process
    Returns:
        location (str): The file path to the extracted evidence.
        number of artifacts (int): The number of files extracted.
    """
    try:
      collected_artifacts = extract_files(
          file_name=_PG_CONF_NAME,
          disk_path=evidence.local_path, output_dir=os.path.join(
              self.output_dir, 'artifacts'), credentials=evidence.credentials)
    except TurbiniaException as exception:
      raise TurbiniaException(
          'artifact extraction failed: {0:s}'.format(str(exception)))

    # Extract base dir from our list of collected artifacts
    location = os.path.dirname(collected_artifacts[0])

    return (location, len(collected_artifacts))

  def _extract_data_dir(self, location, result):
    """Attempts to extract the data_directory value

    Args:
      location : Directory of files extracted from the disk.
      result (TurbiniaTaskResult): Used to log messages.

    Returns:
      data_dirs (list): List of locations of pgsql databases
    """
    data_dirs = []
    for dirs, _, _ in os.walk(location):
      try:
        grep = subprocess.run(
            ['grep', r'data_directory',
             os.path.join(dirs, _PG_CONF_NAME)], check=False, text=True,
            capture_output=True)
        if grep.returncode != 0:
          continue

        for directive in grep.stdout.strip().split('\n'):
          parts = directive.split("'")
          if len(parts) == 3:
            data_dirs.append(parts[1])
          else:
            result.log(
                'Unable to parse data_dir directive: {0:s}'.format(directive))
      except subprocess.CalledProcessError as exception:
        raise TurbiniaException(
            'Unable to grep Postgres config file: {0:s}'.format(str(exception)))

    return data_dirs

  def _extract_creds(self, locations, evidence):
    """Attempts to extract raw encrypted credentials from the database

    Args:
      locations : Dead disk database dirs.
      evidence (Evidence object):  The evidence to process

    Returns:
      hashnames (dict): Dict mapping hash back to username.
    """
    hashnames = {}
    for location in locations:
      dir = os.path.normpath(evidence.local_path + location)
      try:
        grep = subprocess.run(
            ['sudo', 'egrep', '-hari', r'md5[a-zA-Z0-9]{32}', dir], check=False,
            text=False, capture_output=True)
        if grep.returncode != 0:
          continue
      except subprocess.CalledProcessError as exception:
        raise TurbiniaException(
            'Unable to grep raw database file: {0:s}'.format(str(exception)))

      # Process the raw binary data
      raw_lines = str(grep.stdout).split('\\n')
      for line in raw_lines:
        values = line.replace('\\x00', '').replace('\\x01', '')
        m = re.match(_CREDS_REGEXP, values[2:])
        if not m:
          continue
        (username, passwdhash) = (m.group('username'), m.group('password'))
        if passwdhash[3:] not in hashnames:
          hashnames[passwdhash[3:]] = str(username)
    return hashnames

  def _analyse_postgres_creds(self, hashnames, timeout=300):
    """Attempt to brute force extracted PostgreSQL credentials.

    Args:
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

    # 0 is "md5"
    weak_passwords = bruteforce_password_hashes(
        [v + ':' + k for (k, v) in hashnames.items()], tmp_dir=self.tmp_dir,
        timeout=timeout, extra_args='--username -m 0')

    if weak_passwords:
      priority = Priority.CRITICAL
      summary = 'PostgreSQL analysis found {0:d} weak password(s)'.format(
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