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
"""Task for analysing systemd services."""

from __future__ import unicode_literals

import os
import re

from turbinia.evidence import EvidenceState as state
from turbinia.evidence import ReportText
from turbinia.lib import text_formatter as fmt
from turbinia.workers import TurbiniaTask
from turbinia.workers import Priority


class SystemdAnalysisTask(TurbiniaTask):
  """Task to analyze systemd services."""

  REQUIRED_STATES = [
      state.ATTACHED, state.CONTAINER_MOUNTED, state.DECOMPRESSED
  ]

  def run(self, evidence, result):
    """Run the systemd service analysis worker.

    Args:
        evidence (Evidence object):  The evidence we will process.
        result (TurbiniaTaskResult): The object to place task results into.

    Returns:
        TurbiniaTaskResult object.
    """
    # Where to store the resulting output file.
    output_file_name = 'systemd_services_analysis.txt'
    output_file_path = os.path.join(self.output_dir, output_file_name)
    # Set the output file as the data source for the output evidence.
    output_evidence = ReportText(source_path=output_file_path)

    # Read the input file
    with open(evidence.local_path, 'r') as input_file:
      try:
        services = input_file.read()
      except UnicodeDecodeError as exception:
        message = 'Error parsing systemd services {0:s}: {1!s}'.format(
            evidence.local_path, exception)
        result.log(message)
        result.close(self, success=False, status=message)
        return result

    (report, priority, summary) = self.check_systemd_services(services)
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

  def check_systemd_services(self, services):
    """Analyze systemd services.

    Args:
      services (str): file content.

    Returns:
      Tuple(
        report_text(str): The report data
        report_priority(int): The priority of the report (0 - 100)
        summary(str): A summary of the report (used for task status)
      )
    """
    findings = []
    suspicious_binary_location = re.compile(
        r'ExecStart=\/(?!usr\/local\/bin|usr\/sbin|usr\/bin|bin|usr\/libexec|sbin|usr\/lib|lib).+',
        re.IGNORECASE | re.MULTILINE)

    if re.search(suspicious_binary_location, services):
      findings.append(fmt.bullet('Binary was located in a suspicious location'))

    if findings:
      summary = 'Suspicious service found.'
      findings.insert(0, fmt.heading4(fmt.bold(summary)))
      report = '\n'.join(findings)
      return (report, Priority.HIGH, summary)

    report = 'No suspicious services found'
    return (report, Priority.LOW, report)
