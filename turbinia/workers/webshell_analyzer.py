# -*- coding: utf-8 -*-
# Copyright 2017 Google Inc.
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
"""Task for detecting webshells"""

from __future__ import unicode_literals

import os
import json
from turbinia import TurbiniaException

from turbinia.evidence import EvidenceState as state
from turbinia.evidence import ReportText
from turbinia.workers import TurbiniaTask
from turbinia.workers import Priority
from turbinia.lib import text_formatter as fmt


class WebshellAnalyzerTask(TurbiniaTask):
  """Task for detecting webshells"""

  REQUIRED_STATES = [state.ATTACHED, state.MOUNTED, state.CONTAINER_MOUNTED]

  def run(self, evidence, result):
    """Run webshell-analyzer

    Args:
        evidence (Evidence object):  The evidence we will process.
        result (TurbiniaTaskResult): The object to place task results into.

    Returns:
        TurbiniaTaskResult object.
    """
    #output file
    output_file_name = 'webshellanalyzer.txt'
    #Create path to write output file
    output_file_path = os.path.join(self.output_dir, output_file_name)
    #Create evidence object
    output_evidence = ReportText(source_path=output_file_path)

    try:
      (report, priority, summary) = self.find_webshells(result, evidence)
    except TurbiniaException as exception:
      result.close(
          self, success=False, status='Unable to run wsa: {0:s}'.format(
              str(exception)))
      return result

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

  def find_webshells(self, result, evidence):

    stdout_file = os.path.join(
        self.output_dir, '{0:s}_webshells_stdout.log'.format(self.id))

    scan_directory = ['/var/']

    cmd = [
        'sudo', '/opt/webshell-analyzer/wsa', '-dir',
        evidence.local_path + scan_directory
    ]

    result = self.execute(cmd, result, stdout_file=stdout_file)

    findings = []
    priority = Priority.LOW
    summary = 'No webshells were found'

    try:
      with open(stdout_file, 'r') as shells:
        for line in shells:
          try:
            json_data = json.loads(line)
          except (TypeError, ValueError) as e:
            raise TurbiniaException('Error decoding JSON')
          if json_data.get('filePath'):
            findings.append(str(json_data))
    except FileNotFoundError:
      return ('No webshells found')

    if findings:
      summary = 'Webshell Analyzer found {0:d} webshell(s)'.format(
          len(findings))
      priority = priority.HIGH
      findings.insert(0, fmt.heading1(fmt.bold(summary)))
      report = '\n'.join(findings)
      return (report, priority, summary)

    return (summary, priority, summary)