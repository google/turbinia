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
"""Task for analysing Tomcat files."""

from __future__ import unicode_literals

import os
import re

from turbinia.evidence import ReportText
from turbinia.evidence import EvidenceState as state
from turbinia.lib import text_formatter as fmt
from turbinia.workers import TurbiniaTask
from turbinia.workers import Priority


class TomcatAnalysisTask(TurbiniaTask):
  """Task to analyze a Tomcat file."""

  REQUIRED_STATES = [state.ATTACHED, state.CONTAINER_MOUNTED]

  def run(self, evidence, result):
    """Run the Tomcat analysis worker.

    Args:
        evidence (Evidence object):  The evidence we will process.
        result (TurbiniaTaskResult): The object to place task results into.

    Returns:
        TurbiniaTaskResult object.
    """

    # Where to store the resulting output file.
    output_file_name = 'tomcat_analysis.txt'
    output_file_path = os.path.join(self.output_dir, output_file_name)
    # Set the output file as the data source for the output evidence.
    output_evidence = ReportText(source_path=output_file_path)

    # Read the input file
    with open(evidence.local_path, 'r') as input_file:
      tomcat_file = input_file.read()

    (report, priority, summary) = self.analyse_tomcat_file(tomcat_file)
    result.report_priority = priority
    result.report_data = report
    output_evidence.text_data = report

    # Write the report to the output file.
    with open(output_file_path, 'w') as fh:
      fh.write(output_evidence.text_data.encode('utf-8'))

    # Add the resulting evidence to the result object.
    result.add_evidence(output_evidence, evidence.config)
    result.close(self, success=True, status=summary)
    return result

  def analyse_tomcat_file(self, tomcat_file):
    """Analyse a Tomcat file.

    - Search for clear text password entries in user configuration file
    - Search for .war deployment
    - Search for management control panel activity

    Args:
      tomcat_file (str): Tomcat file content.
    Returns:
      Tuple(
        report_text(str): The report data
        report_priority(int): The priority of the report (0 - 100)
        summary(str): A summary of the report (used for task status)
      )
    """
    findings = []

    tomcat_user_passwords_re = re.compile('(^.*password.*)', re.MULTILINE)
    tomcat_deploy_re = re.compile(
        '(^.*Deploying web application archive.*)', re.MULTILINE)
    tomcat_manager_activity_re = re.compile(
        '(^.*POST /manager/html/upload.*)', re.MULTILINE)

    count = 0
    for password_entry in re.findall(tomcat_user_passwords_re, tomcat_file):
      findings.append(fmt.bullet('Tomcat user: ' + password_entry.strip()))
      count += 1

    for deployment_entry in re.findall(tomcat_deploy_re, tomcat_file):
      findings.append(
          fmt.bullet('Tomcat App Deployed: ' + deployment_entry.strip()))
      count += 1

    for mgmt_entry in re.findall(tomcat_manager_activity_re, tomcat_file):
      findings.append(fmt.bullet('Tomcat Management: ' + mgmt_entry.strip()))
      count += 1

    if findings:
      msg = 'Tomcat analysis found {0:d} results'.format(count)
      findings.insert(0, fmt.heading4(fmt.bold(msg)))
      report = '\n'.join(findings)
      return (report, Priority.HIGH, msg)

    report = 'No Tomcat findings to report'
    return (report, Priority.LOW, report)
