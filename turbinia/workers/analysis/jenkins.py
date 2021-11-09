# -*- coding: utf-8 -*-
# Copyright 2018 Google Inc.
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
"""Task for analysing Jenkins."""

from __future__ import unicode_literals

import os
import re

from turbinia import TurbiniaException
from turbinia.evidence import EvidenceState as state
from turbinia.evidence import ReportText
from turbinia.lib import text_formatter as fmt
from turbinia.workers import TurbiniaTask
from turbinia.workers import Priority
from turbinia.lib.utils import extract_files
from turbinia.lib.utils import bruteforce_password_hashes


class JenkinsAnalysisTask(TurbiniaTask):
  """Task to analyze a Jenkins install."""

  REQUIRED_STATES = [state.ATTACHED, state.CONTAINER_MOUNTED]

  TASK_CONFIG = {
      # This is the length of time in seconds that the collected passwords will
      # be bruteforced.
      'bruteforce_timeout': 300
  }

  def run(self, evidence, result):
    """Run the Jenkins worker.

    Args:
        evidence (Evidence object):  The evidence to process
        result (TurbiniaTaskResult): The object to place task results into.

    Returns:
        TurbiniaTaskResult object.
    """

    # Where to store the resulting output file.
    output_file_name = 'jenkins_analysis.txt'
    output_file_path = os.path.join(self.output_dir, output_file_name)

    # What type of evidence we should output.
    output_evidence = ReportText(source_path=output_file_path)

    # TODO(aarontp): We should find a more optimal solution for this because
    # this requires traversing the entire filesystem and extracting more files
    # than we need.  Tracked in https://github.com/google/turbinia/issues/402
    try:
      collected_artifacts = extract_files(
          file_name='config.xml',
          disk_path=evidence.local_path, output_dir=os.path.join(
              self.output_dir, 'artifacts'), credentials=evidence.credentials)
    except TurbiniaException as e:
      result.close(self, success=False, status=str(e))
      return result

    jenkins_artifacts = []
    jenkins_re = re.compile(r'^.*jenkins[^\/]*(\/users\/[^\/]+)*\/config\.xml$')
    for collected_artifact in collected_artifacts:
      if re.match(jenkins_re, collected_artifact):
        jenkins_artifacts.append(collected_artifact)

    version = None
    credentials = []
    for filepath in jenkins_artifacts:
      with open(filepath, 'r') as input_file:
        config = input_file.read()

      extracted_version = self._extract_jenkins_version(config)
      extracted_credentials = self._extract_jenkins_credentials(config)

      if extracted_version:
        version = extracted_version

      credentials.extend(extracted_credentials)

    timeout = self.task_config.get('bruteforce_timeout')
    (report, priority, summary) = self.analyze_jenkins(
        version, credentials, timeout=timeout)
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

  @staticmethod
  def _extract_jenkins_version(config):
    """Extract version from Jenkins configuration files.

    Args:
      config (str): configuration file content.

    Returns:
      str: The version of Jenkins.
    """
    version = None
    version_re = re.compile('<version>(.*)</version>')
    version_match = re.search(version_re, config)

    if version_match:
      version = version_match.group(1)

    return version

  @staticmethod
  def _extract_jenkins_credentials(config):
    """Extract credentials from Jenkins configuration files.

    Args:
      config (str): configuration file content.

    Returns:
      list: of tuples with username and password hash.
    """
    credentials = []
    password_hash_re = re.compile('<passwordHash>#jbcrypt:(.*)</passwordHash>')
    username_re = re.compile('<fullName>(.*)</fullName>')

    password_hash_match = re.search(password_hash_re, config)
    username_match = re.search(username_re, config)

    if username_match and password_hash_match:
      username = username_match.group(1)
      password_hash = password_hash_match.group(1)
      credentials.append((username, password_hash))

    return credentials

  @staticmethod
  def analyze_jenkins(version, credentials, timeout=300):
    """Analyses a Jenkins configuration.

    Args:
      version (str): Version of Jenkins.
      credentials (list): of tuples with username and password hash.
      timeout (int): Time in seconds to run password bruteforcing.

    Returns:
      Tuple(
        report_text(str): The report data
        report_priority(int): The priority of the report (0 - 100)
        summary(str): A summary of the report (used for task status)
      )
    """
    report = []
    summary = ''
    priority = Priority.LOW
    credentials_registry = {hash: username for username, hash in credentials}

    # '3200' is "bcrypt $2*$, Blowfish (Unix)"
    weak_passwords = bruteforce_password_hashes(
        credentials_registry.keys(), tmp_dir=None, timeout=timeout,
        extra_args='-m 3200')

    if not version:
      version = 'Unknown'
    report.append(fmt.bullet('Jenkins version: {0:s}'.format(version)))

    if weak_passwords:
      priority = Priority.CRITICAL
      summary = 'Jenkins analysis found potential issues'
      report.insert(0, fmt.heading4(fmt.bold(summary)))
      line = '{0:n} weak password(s) found:'.format(len(weak_passwords))
      report.append(fmt.bullet(fmt.bold(line)))
      for password_hash, plaintext in weak_passwords:
        line = 'User "{0:s}" with password "{1:s}"'.format(
            credentials_registry.get(password_hash), plaintext)
        report.append(fmt.bullet(line, level=2))
    elif credentials_registry or version != 'Unknown':
      summary = (
          'Jenkins version {0:s} found with {1:d} credentials, but no issues '
          'detected'.format(version, len(credentials_registry)))
      report.insert(0, fmt.heading4(summary))
      priority = Priority.MEDIUM
    else:
      summary = 'No Jenkins instance found'
      report.insert(0, fmt.heading4(summary))

    report = '\n'.join(report)
    return (report, priority, summary)
