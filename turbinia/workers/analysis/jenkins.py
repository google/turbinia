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
from turbinia.evidence import ReportText
from turbinia.workers import TurbiniaTask
from turbinia.lib.utils import extract_artifacts
from turbinia.lib.utils import bruteforce_password_hashes


class JenkinsAnalysisTask(TurbiniaTask):
  """Task to analyze a Jenkins install."""

  def run(self, evidence, result):
    """Run the Jenkins worker.

    Args:
        evidence (Evidence object):  The evidence to process
        result (TurbiniaTaskResult): The object to place task results into.

    Returns:
        TurbiniaTaskResult object.
    """
    # What type of evidence we should output.
    output_evidence = ReportText()

    # Where to store the resulting output file.
    output_file_name = 'jenkins_analysis.txt'
    output_file_path = os.path.join(self.output_dir, output_file_name)

    # Set the output file as the data source for the output evidence.
    output_evidence.local_path = output_file_path

    try:
      collected_artifacts = extract_artifacts(
          artifact_names=['JenkinsConfigFile'],
          disk_path=evidence.local_path,
          output_dir=os.path.join(self.output_dir, 'artifacts')
      )
    except TurbiniaException as e:
      result.close(self, success=False, status=str(e))
      return result

    version = None
    credentials = []
    for filepath in collected_artifacts:
      with open(filepath, 'r') as input_file:
        config = input_file.read()

      extracted_version = self._extract_jenkins_version(config)
      extracted_credentials = self._extract_jenkins_credentials(config)

      if extracted_version:
        version = extracted_version

      credentials.extend(extracted_credentials)

    analysis_report = self.analyze_jenkins(version, credentials)
    output_evidence.text_data = analysis_report

    # Write the report to the output file.
    with open(output_file_path, 'w') as fh:
      fh.write(output_evidence.text_data.encode('utf8'))
      fh.write('\n'.encode('utf8'))

    # Add the resulting evidence to the result object.
    result.add_evidence(output_evidence, evidence.config)
    if analysis_report:
      status = analysis_report[0].strip()
    else:
      status = 'Jenkins analysis found no potential issues'
    result.close(self, success=True, status=status)

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
  def analyze_jenkins(version, credentials):
    """Analyses a Jenkins configuration.

    Args:
      version (str): Version of Jenkins.
      credentials (list): of tuples with username and password hash.

    Returns:
      str: of description of security of Jenkins configuration file.
    """
    findings = []
    credentials_registry = {hash: username for username, hash in credentials}
    # TODO: Add timeout parameter when dynamic configuration is ready.
    # Ref: https://github.com/google/turbinia/issues/244
    weak_passwords = bruteforce_password_hashes(credentials_registry.keys())

    if not version:
      version = 'Unknown'
    findings.append('Jenkins version: {0:s}'.format(version))

    if weak_passwords:
      findings.insert(0, 'Jenkins analysis found potential issues.\n')
      findings.append(
          '{0:n} weak password(s) found:'.format(len(weak_passwords)))
      for password_hash, plaintext in weak_passwords:
        findings.append(' - User "{0:s}" with password "{1:s}"'.format(
            credentials_registry.get(password_hash), plaintext))

    return '\n'.join(findings)
