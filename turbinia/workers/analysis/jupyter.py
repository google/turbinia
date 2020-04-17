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
from turbinia.evidence import ReportText
from turbinia.lib import text_formatter as fmt
from turbinia.workers import TurbiniaTask
from turbinia.workers import Priority
from turbinia.lib.utils import extract_files
from turbinia.lib.utils import bruteforce_password_hashes


class JupyterAnalysisTask(TurbiniaTask):
  """Task to analyze a Jupyter Notebook config."""

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
    # with open(evidence.local_path, 'r') as input_file:
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
    """Extract version from Jupyter configuration files.

    Args:
      config (str): configuration file content.

    Returns:
      str: The version of Jupyter.
    """
    import logging
    findings = []
    for line in jupyter_config.split('\n'):

      if all(x in line for x in ['disable_check_xsrf', 'True']):
        findings.append(fmt.bullet('XSRF protection is disabled.'))
        continue
      if all(x in line for x in ['allow_root', 'True']):
        findings.append(fmt.bullet('Jupyter Notebook runs as admin.'))
        continue
      if 'NotebookApp.port' in line:
        port = line.split('=')[1].replace(' ', '')
        if port == '0':
          findings.append(fmt.bullet('Jupyter Notebook listens on all ports.'))
          continue
      if 'password' in line:
        if all(x in line for x in ['required', 'False']):
          findings.append(
              fmt.bullet('Jupyter Notebook is not password protected.'))
          continue
        if 'required' not in line:
          password_hash = line.split('=')[1].replace(' ', '')
          if password_hash == "''":
            findings.append(
                fmt.bullet('There is no password for this Jupyter Notebook.'))

    if findings:
      summary = 'Insecure Jupyter Notebook configuration found.'
      findings.insert(0, fmt.heading4(fmt.bold(summary)))
      report = '\n'.join(findings)
      return (report, Priority.HIGH, summary)

    report = 'No issues found in Jupyter Notebook  configuration.'
    logging.error('its report {}'.format(report))
    return (report, Priority.LOW, report)
