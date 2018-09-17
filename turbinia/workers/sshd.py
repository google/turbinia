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
"""Task for analysing sshd_config files."""

from __future__ import unicode_literals

import os
import re

from turbinia.evidence import ReportText
from turbinia.workers import TurbiniaTask


class SSHDAnalysisTask(TurbiniaTask):
  """Task to analyze a sshd_config file."""

  def run(self, evidence, result):
    """Run the sshd_config analysis worker.

    Args:
       evidence (Evidence object):  The evidence to process
       result (TurbiniaTaskResult): The object to place task results into.

    Returns:
      TurbiniaTaskResult object.
    """
    # What type of evidence we should output.
    output_evidence = ReportText()

    # Where to store the resulting output file.
    output_file_name = 'sshd_config_analysis.txt'
    output_file_path = os.path.join(self.output_dir, output_file_name)
    # Set the output file as the data source for the output evidence.
    output_evidence.local_path = output_file_path

    # Read the input file
    with open(evidence.local_path, 'r') as input_file:
      sshd_config = input_file.read()

    analysis = self.analyse_sshd_config(sshd_config)
    output_evidence.text_data = analysis

    # Write the report to the output file.
    with open(output_file_path, 'w') as fh:
      fh.write(output_evidence.text_data.encode('utf-8'))

    # Add the resulting evidence to the result object.
    result.add_evidence(output_evidence, evidence.config)
    result.close(self, success=True)
    return result

  def analyse_sshd_config(self, config):
    """Analyses an SSH configuration.

    Args:
      config (str): configuration file content.

    Returns:
      str: description of security of SSHD configuration file.
    """
    findings = []
    permit_root_login_re = re.compile(
        r'^\s*PermitRootLogin\s*(yes|prohibit-password|without-password)',
        re.IGNORECASE | re.MULTILINE)
    password_authentication_re = re.compile(
        r'^\s*PasswordAuthentication[\s"]*No', re.IGNORECASE | re.MULTILINE)
    permit_empty_passwords_re = re.compile(
        r'^\s*PermitEmptyPasswords[\s"]*Yes', re.IGNORECASE | re.MULTILINE)

    if re.search(permit_root_login_re, config):
      findings.append('\tRoot login enabled.')

    if not re.search(password_authentication_re, config):
      findings.append('\tPassword authentication enabled.')

    if re.search(permit_empty_passwords_re, config):
      findings.append('\tEmpty passwords permitted.')

    if findings:
      findings.insert(0, 'Insecure SSH configuration found.')
      return '\n'.join(findings)

    return 'No issues found in SSH configuration'
