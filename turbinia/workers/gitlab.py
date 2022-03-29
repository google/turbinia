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
"""Task for analysing Gitlab instances."""

from __future__ import unicode_literals

import os
import glob

from turbinia.evidence import EvidenceState as state
from turbinia.evidence import ReportText
from turbinia.lib import text_formatter as fmt
from turbinia.workers import TurbiniaTask
from turbinia.workers import Priority


class GitlabTask(TurbiniaTask):
  """Task to analyze Gitlabs."""

  REQUIRED_STATES = [
      state.ATTACHED, state.CONTAINER_MOUNTED, state.DECOMPRESSED
  ]

  def run(self, evidence, result):
    """Run the Gitlab worker.

    Args:
        evidence (Evidence object):  The evidence we will process.
        result (TurbiniaTaskResult): The object to place task results into.

    Returns:
        TurbiniaTaskResult object.
    """
    # Where to store the resulting output file.
    output_file_name = 'gitlab_analysis.txt'
    output_file_path = os.path.join(self.output_dir, output_file_name)
    # Set the output file as the data source for the output evidence.
    output_evidence = ReportText(source_path=output_file_path)

    reports = []
    summaries = []

    # Grep for exif in workhorse logs
    (r, priority, s) = self._is_exif_in_logs(
        result, evidence.local_path,
        os.path.join('var', 'log', 'gitlab', 'workhorse.log'))
    if r != '':
      reports.append(r)
    if s != '':
      summaries.append(s)

    (r, p2, s) = self._is_exif_in_logs(
        result, evidence.local_path,
        os.path.join('var', 'log', 'gitlab', 'gitlab-workhorse', '@*'))
    if r != '':
      reports.append(r)
    if s != '':
      summaries.append(s)
    if p2 < priority:
      priority = p2

    # TODO: Check for Metasploit Module
    # 'https://packetstormsecurity.com/files/160441/GitLab-File-Read-Remote-Code-Execution.html'

    (r, p3, s) = self._is_traversal_in_logs(
        result, evidence.local_path,
        os.path.join('var', 'log', 'gitlab', 'nginx', '*access*'))
    if r != '':
      reports.append(r)
    if s != '':
      summaries.append(s)
    if p3 < priority:
      priority = p3

    if priority == priority.LOW:
      result.close(self, success=True, status='No Gitlab exploitation found')
      return result

    report = " ".join(reports)
    summary = " ".join(summaries)

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

  def _is_exif_in_logs(self, result, basedir, logfiles):
    """Checks to see if there is evidence of the exiftool exploit in the logs.

    Args:
      result (TurbiniaTaskResult): The object to place task results into.
      basedir (str): the root of the evidence.
      logfiles (str): The file(s) to check

    Returns:
      Tuple(
        report_text(str): The report data
        report_priority(int): The priority of the report (0 - 100)
        summary(str): A summary of the report (used for task status)
      )
    """

    check = " ".join(glob.glob(os.path.join(basedir, logfiles)))
    if not len(check):
      return ('', Priority.LOW, '')

    cmd = ['zgrep', '"exiftool command failed"', check]
    ret, result = self.execute(cmd, result, success_codes=[0, 1])
    if ret == 0:
      summary = 'exif exploit detected in {0:s}'.format(logfiles)
      report = fmt.heading4(fmt.bold(summary))
      return (report, Priority.HIGH, summary)

    return ('', Priority.LOW, '')

  def _is_traversal_in_logs(self, result, basedir, logfiles):
    """Checks to see if there is evidence of directory traversal in the logs.

    Args:
      result (TurbiniaTaskResult): The object to place task results into.
      basedir (str): the root of the evidence.
      logfiles (str): The file(s) to check

    Returns:
      Tuple(
        report_text(str): The report data
        report_priority(int): The priority of the report (0 - 100)
        summary(str): A summary of the report (used for task status)
      )
    """

    check = " ".join(glob.glob(os.path.join(basedir, logfiles)))
    if not len(check):
      return ('', Priority.LOW, '')

    cmd = ['zgrep', '"%2F..%2F..%2F..%2F"', check]
    ret, result = self.execute(cmd, result, success_codes=[0, 1])
    if ret == 0:
      summary = 'directory traversal exploit detected in {}'.format(logfiles)
      report = fmt.heading4(fmt.bold(summary))
      return (report, Priority.HIGH, summary)

    return ('', Priority.LOW, '')
