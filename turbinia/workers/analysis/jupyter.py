# -*- coding: utf-8 -*-
# Copyright 2020 Google Inc.
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
"""Task for analysing Jupyter."""

from __future__ import unicode_literals

import os
import re

from turbinia import TurbiniaException
from turbinia.evidence import EvidenceState as state
from turbinia.evidence import ReportText
from turbinia.lib import text_formatter as fmt
from turbinia.workers import TurbiniaTask
from turbinia.workers import Priority


class JupyterAnalysisTask(TurbiniaTask):
  """Task to analyze a Jupyter Notebook config."""

  REQUIRED_STATES = [
      state.ATTACHED, state.DOCKER_MOUNTED, state.PARENT_ATTACHED,
      state.PARENT_MOUNTED
  ]

  def run(self, evidence, result):
    """Run the Jupyter worker.

    Args:
        evidence (Evidence object):  The evidence to process
        result (TurbiniaTaskResult): The object to place task results into.

    Returns:
        TurbiniaTaskResult object.
    """

    # Where to store the resulting output file.
    output_file_name = 'jupyter_analysis.txt'
    output_file_path = os.path.join(self.output_dir, output_file_name)

    # What type of evidence we should output.
    output_evidence = ReportText(source_path=output_file_path)

    # Read the config file.

    jupyter_config = open(evidence.local_path, 'r').read()

    # Extract the config and return the report
    (report, priority, summary) = self.analyse_config(jupyter_config)
    output_evidence.text_data = report
    result.report_priority = priority
    result.report_data = report

    # Write the report to the output file.
    with open(output_file_path, 'w') as fh:
      fh.write(output_evidence.text_data.encode('utf8'))
      fh.write('\n'.encode('utf8'))

    # Add the resulting evidence to the result object.
    result.add_evidence(output_evidence, evidence.config)
    result.close(self, success=True, status=summary)

    return result

  def analyse_config(self, jupyter_config):
    """Extract security related configs from Jupyter configuration files.

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
    num_misconfigs = 0
    for line in jupyter_config.split('\n'):

      if all(x in line for x in ['disable_check_xsrf', 'True']):
        findings.append(fmt.bullet('XSRF protection is disabled.'))
        num_misconfigs += 1
        continue
      if all(x in line for x in ['allow_root', 'True']):
        findings.append(fmt.bullet('Juypter Notebook allowed to run as root.'))
        num_misconfigs += 1
        continue
      if 'NotebookApp.password' in line:
        if all(x in line for x in ['required', 'False']):
          findings.append(
              fmt.bullet(
                  'Password is not required to access this Jupyter Notebook.'))
          num_misconfigs += 1
          continue
        if 'required' not in line:
          password_hash = line.split('=')
          if len(password_hash) > 1:
            if password_hash[1].strip() == "''":
              findings.append(
                  fmt.bullet(
                      'There is no password set for this Jupyter Notebook.'))
              num_misconfigs += 1
      if all(x in line for x in ['allow_remote_access', 'True']):
        findings.append(
            fmt.bullet('Remote access is enabled on this Jupyter Notebook.'))
        num_misconfigs += 1
        continue

    if findings:
      summary = 'Insecure Jupyter Notebook configuration found. Total misconfigs: {}'.format(
          num_misconfigs)
      findings.insert(0, fmt.heading4(fmt.bold(summary)))
      report = '\n'.join(findings)
      return (report, Priority.HIGH, summary)

    report = 'No issues found in Jupyter Notebook  configuration.'
    return (report, Priority.LOW, report)
