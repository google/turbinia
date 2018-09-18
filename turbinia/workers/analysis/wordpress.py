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
"""Task for analysing Wordpress access logs."""

from __future__ import unicode_literals

import gzip
import os
import re

from turbinia.evidence import ReportText
from turbinia.workers import TurbiniaTask


class WordpressAccessLogAnalysisTask(TurbiniaTask):
  """Task to analyze Wordpress access logs."""

  timestamp_regex = re.compile(r'\[(?P<timestamp>.+)\]')

  install_step_regex = re.compile(
      r'POST /wp-admin/install\.php\?step=2', re.IGNORECASE)
  theme_editor_regex = re.compile(
      r'GET /wp-admin/theme-editor\.php\?file=(?P<edited_file>.+\.php)',
      re.IGNORECASE)

  def run(self, evidence, result):
    """Run the Wordpress access log analysis worker.

    Args:
       evidence (Evidence object):  The evidence to process
       result (TurbiniaTaskResult): The object to place task results into.

    Returns:
      TurbiniaTaskResult object.
    """
    # What type of evidence we should output.
    output_evidence = ReportText()

    # Where to store the resulting output file.
    output_file_name = 'wp_acces_log_analysis.txt'
    output_file_path = os.path.join(self.output_dir, output_file_name)
    # Set the output file as the data source for the output evidence.
    output_evidence.local_path = output_file_path

    # Change open function if file is GZIP compressed.
    open_function = open
    if evidence.local_path.lower().endswith('gz'):
      open_function = gzip.open

    # Read the input file
    with open_function(evidence.local_path, 'rb') as input_file:
      access_logs_content = input_file.read().decode('utf-8')

    analysis = self.analyze_wp_access_logs(access_logs_content)
    output_evidence.text_data = analysis

    # Write the report to the output file.
    with open(output_file_path, 'w') as fh:
      fh.write(output_evidence.text_data.encode('utf-8'))

    # Add the resulting evidence to the result object.
    result.add_evidence(output_evidence, evidence.config)
    status = analysis.split('\n')[0]
    result.close(self, success=True, status=status)
    return result

  def _get_timestamp(self, log_line):
    """Extracts a timestamp from an access log line."""
    match = self.timestamp_regex.search(log_line)
    if match:
      return match.group('timestamp')
    return '[N/A]'

  def analyze_wp_access_logs(self, config):
    """Analyses access logs containing Wordpress traffic.

    Args:
      config (str): access log file content.

    Returns:
      str: Activity summary of the wordpress installation.
    """
    findings = []
    findings_summary = set()

    for log_line in config.split('\n'):

      if self.install_step_regex.search(log_line):
        findings.append(
            '\t{0:s}: Wordpress installation successful'.format(
                self._get_timestamp(log_line)))
        findings_summary.add('install')

      match = self.theme_editor_regex.search(log_line)
      if match:
        findings.append(
            '\t{0:s}: Wordpress theme editor edited file ({1:s})\n'.format(
                self._get_timestamp(log_line), match.group('edited_file')))
        findings_summary.add('theme_edit')

    if findings:
      findings.insert(0, 'Wordpress access logs found ({0:s})'.format(
          ', '.join(sorted(list(findings_summary)))))
      return '\n'.join(findings)

    return 'No Wordpress install or theme editing found in access logs'
