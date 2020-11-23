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
from turbinia.lib import text_formatter as fmt
from turbinia.workers import TurbiniaTask
from turbinia.workers import Priority


class SSHDAnalysisTask(TurbiniaTask):
  """Task to analyze a sshd_config file."""

  def run(self, evidence, result):
    """Run the sshd_config analysis worker.

    Args:
        evidence (Evidence object):  The evidence we will process.
        result (TurbiniaTaskResult): The object to place task results into.

    Returns:
        TurbiniaTaskResult object.
    """
    # Where to store the resulting output file.
    output_file_name = 'sshd_config_analysis.txt'
    output_file_path = os.path.join(self.output_dir, output_file_name)
    # Set the output file as the data source for the output evidence.
    output_evidence = ReportText(source_path=output_file_path)

    # Read the input file
    with open(evidence.local_path, 'r') as input_file:
      sshd_config = input_file.read()

    (report, priority, summary) = self.analyse_sshd_config(sshd_config)
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

  def analyse_sshd_config(self, config):
    """Analyses an SSH configuration.

    Args:
      config (str): configuration file content.

    Returns:
      Tuple(
        report_text(str): The report data
        report_priority(int): The priority of the report (0 - 100)
        summary(str): A summary of the report (used for task status)
      )
    """
    findings = []
    permit_root_login_re = re.compile(
        r'^\s*PermitRootLogin\s*(yes|prohibit-password|without-password)',
        re.IGNORECASE | re.MULTILINE)
    password_authentication_re = re.compile(
        r'^\s*PasswordAuthentication[\s"]*yes', re.IGNORECASE | re.MULTILINE)
    permit_empty_passwords_re = re.compile(
        r'^\s*PermitEmptyPasswords[\s"]*Yes', re.IGNORECASE | re.MULTILINE)

    if re.search(permit_root_login_re, config):
      findings.append(fmt.bullet('Root login enabled.'))

    if re.search(password_authentication_re, config):
      findings.append(fmt.bullet('Password authentication enabled.'))

    if re.search(permit_empty_passwords_re, config):
      findings.append(fmt.bullet('Empty passwords permitted.'))

    if findings:
      summary = 'Insecure SSH configuration found.'
      findings.insert(0, fmt.heading4(fmt.bold(summary)))
      report = '\n'.join(findings)
      return (report, Priority.HIGH, summary)

    report = 'No issues found in SSH configuration'
    return (report, Priority.LOW, report)
