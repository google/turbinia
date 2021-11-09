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
"""Task for running Loki on drives & directories."""

import csv
import os
from turbinia import TurbiniaException

from turbinia.evidence import EvidenceState as state
from turbinia.evidence import ReportText
from turbinia.lib import text_formatter as fmt
from turbinia.workers import Priority
from turbinia.workers import TurbiniaTask


class LokiAnalysisTask(TurbiniaTask):
  """Task to use Loki to analyse files."""

  REQUIRED_STATES = [
      state.ATTACHED, state.MOUNTED, state.CONTAINER_MOUNTED, state.DECOMPRESSED
  ]

  def run(self, evidence, result):
    """Run the Loki worker.

    Args:
        evidence (Evidence object):  The evidence to process
        result (TurbiniaTaskResult): The object to place task results into.
    Returns:
        TurbiniaTaskResult object.
    """
    # Where to store the resulting output file.
    output_file_name = 'loki_analysis.txt'
    output_file_path = os.path.join(self.output_dir, output_file_name)

    # What type of evidence we should output.
    output_evidence = ReportText(source_path=output_file_path)

    try:
      (report, priority, summary) = self.runLoki(result, evidence)
    except TurbiniaException as e:
      result.close(
          self, success=False, status='Unable to run Loki: {0:s}'.format(
              str(e)))
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

  def runLoki(self, result, evidence):
    log_file = os.path.join(self.output_dir, 'loki.log')
    stdout_file = os.path.join(self.output_dir, 'loki_stdout.log')
    stderr_file = os.path.join(self.output_dir, 'loki_stderr.log')

    cmd = [
        'python', '/opt/loki/loki.py', '-w', '0', '--csv', '--intense',
        '--noprocscan', '--dontwait', '--noindicator', '-l', log_file, '-p',
        evidence.local_path
    ]

    (ret, result) = self.execute(
        cmd, result, log_files=[log_file], stdout_file=stdout_file,
        stderr_file=stderr_file, cwd='/opt/loki/')

    if ret != 0:
      raise TurbiniaException('Return code: {0:d}'.format(ret))

    report = []
    summary = 'No Loki threats found'
    priority = Priority.LOW

    report_lines = []
    with open(stdout_file, 'r') as loki_report_csv:
      lokireader = csv.DictReader(
          loki_report_csv, fieldnames=['Time', 'Hostname', 'Level', 'Log'])
      for row in lokireader:
        if row['Level'] == 'ALERT':
          report_lines.append(row['Log'])

    if report_lines:
      priority = Priority.HIGH
      summary = 'Loki analysis found {0:d} alert(s)'.format(len(report_lines))
      report.insert(0, fmt.heading4(fmt.bold(summary)))
      line = '{0:n} alerts(s) found:'.format(len(report_lines))
      report.append(fmt.bullet(fmt.bold(line)))
      for line in report_lines:
        report.append(fmt.bullet(line, level=2))

    report = '\n'.join(report)
    return (report, priority, summary)
