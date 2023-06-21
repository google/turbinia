# -*- coding: utf-8 -*-
# Copyright 2022 Google Inc.
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
"""Task for running Yara on drives & directories."""

import json
import os
import re

from turbinia import config
from turbinia import TurbiniaException

from turbinia.evidence import EvidenceState as state
from turbinia.evidence import ReportText
from turbinia.lib import file_helpers
from turbinia.lib import text_formatter as fmt
from turbinia.workers import Priority
from turbinia.workers import TurbiniaTask


class YaraAnalysisTask(TurbiniaTask):
  """Task to use Yara to analyse files."""

  REQUIRED_STATES = [
      state.ATTACHED, state.MOUNTED, state.CONTAINER_MOUNTED, state.DECOMPRESSED
  ]

  # Task configuration variables from recipe
  TASK_CONFIG = {
      # Only hits for rules greater than this score
      # will be output.
      'minscore': None
  }

  def run(self, evidence, result):
    """Run the Yara worker.

    Args:
        evidence (Evidence object):  The evidence to process
        result (TurbiniaTaskResult): The object to place task results into.
    Returns:
        TurbiniaTaskResult object.
    """
    # Where to store the resulting output file.
    output_file_name = 'yara_analysis.txt'
    output_file_path = os.path.join(self.output_dir, output_file_name)

    # What type of evidence we should output.
    output_evidence = ReportText(source_path=output_file_path)

    try:
      (report, priority, summary) = self.runFraken(result, evidence)
    except TurbiniaException as exception:
      result.close(
          self, success=False,
          status=f'Unable to run Fraken: {str(exception):s}')
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

  def runFraken(self, result, evidence):
    """Runs Fraken.

      Args:
        evidence (Evidence object):  The evidence to process
        result (TurbiniaTaskResult): The object to place task results into.
      Raises:
        TurbiniaException
      Returns:
        report (tuple): A 3-tuple containing a report, priority and summary.
    """
    stdout_file = os.path.join(
        self.output_dir, f'{self.id:s}_fraken_stdout.log')
    stderr_file = os.path.join(
        self.output_dir, f'{self.id:s}_fraken_stderr.log')

    cmd = [
        'sudo', '/opt/fraken/fraken', '-rules', '/opt/signature-base/',
        '-folder', evidence.local_path
    ]
    if self.task_config.get('minscore'):
      cmd.extend(['-minscore', self.task_config.get('minscore')])

    yr = self.task_config.get('yara_rules')
    if yr:
      file_path = file_helpers.write_str_to_temp_file(
          yr, preferred_dir=self.tmp_dir)
      cmd.extend(['-extrayara', file_path])

    (ret, result) = self.execute(
        cmd, result, stderr_file=stderr_file, stdout_file=stdout_file)

    if ret != 0:
      if os.path.exists(stderr_file):
        with open(stderr_file, 'r') as f:
          error = f.readlines()
      else:
        error = "Unknown (no stderr)"
      raise TurbiniaException(f'Return code: {ret:d}. Error: {error!s}')

    report = []
    summary = 'No Yara rules matched'
    priority = Priority.LOW

    config.LoadConfig()
    dirRE = re.compile(r"{0!s}/.*?/".format(config.MOUNT_DIR_PREFIX))

    report_lines = []
    try:
      with open(stdout_file, 'r') as fraken_report:
        try:
          fraken_output = json.load(fraken_report)
        except (TypeError, ValueError, FileNotFoundError,
                json.JSONDecodeError) as exception:
          raise TurbiniaException(
              f'Error decoding JSON output from fraken: {exception!s}')
        for row in fraken_output:
          report_lines.append(
              ' - '.join([
                  dirRE.sub("/", row['ImagePath']), row['SHA256'],
                  row['Signature'],
                  row.get('Description', ''),
                  row.get('Reference', ''),
                  str(row.get('Score', 0))
              ]))
    except FileNotFoundError:
      pass  # No Yara rules matched

    if report_lines:
      priority = Priority.HIGH
      summary = f'Yara analysis found {len(report_lines):d} alert(s)'
      report.insert(0, fmt.heading4(fmt.bold(summary)))
      line = f'{len(report_lines):n} alerts(s) found:'
      report.append(fmt.bullet(fmt.bold(line)))
      for line in report_lines:
        report.append(fmt.bullet(line, level=2))

    report = '\n'.join(report)
    return (report, priority, summary)
