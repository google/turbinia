# -*- coding: utf-8 -*-
# Copyright 2024 Google Inc.
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
"""Task for analysing saved Chrome Credentials."""

import os
import sqlite3

from turbinia import TurbiniaException

from turbinia.evidence import EvidenceState as state
from turbinia.evidence import ReportText
from turbinia.lib import text_formatter as fmt
from turbinia.lib.utils import extract_data_stream
from turbinia.workers import Priority
from turbinia.workers import TurbiniaTask


class ChromeCredsAnalysisTask(TurbiniaTask):
  """Task to analyze a Chrome Login Data file."""

  # Does not need to be MOUNTED as this Task uses extract_data_stream()
  REQUIRED_STATES = [state.ATTACHED, state.CONTAINER_MOUNTED]

  def run(self, evidence, result):
    """Run the ChromeCreds worker.

    Args:
        evidence (Evidence object):  The evidence to process
        result (TurbiniaTaskResult): The object to place task results into.

    Returns:
        TurbiniaTaskResult object.
    """

    # Where to store the resulting output file.
    output_file_name = 'chrome_creds_analysis.txt'
    output_file_path = os.path.join(self.output_dir, output_file_name)

    # What type of evidence we should output.
    output_evidence = ReportText(source_path=output_file_path)

    try:
      collected_artifacts = extract_data_stream(
          artifact_names=['ChromiumBasedBrowsersLoginDataDatabaseFile'],
          disk_path=evidence.local_path, output_dir=self.output_dir,
          credentials=evidence.credentials)
    except TurbiniaException as exception:
      result.close(self, success=False, status=str(exception))
      return result

    extracted_creds = {}

    for collected_artifact in collected_artifacts:
      extracted_creds.update(self._extract_chrome_creds(collected_artifact))

    for key in extracted_creds:
      extracted_creds[key] = list(set(extracted_creds[key]))

    (report, priority, summary) = self.summarise_creds(extracted_creds)

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

  @staticmethod
  def summarise_creds(creds):
    """Summarise the sum total of extracted credentials.
    
    Args:
      creds (dict[List[str]]): dict mapping domain to a list of usernames.

    Returns:
      Tuple(
        report_text(str): The report data
        report_priority(int): The priority of the report (0 - 100)
        summary(str): A summary of the report (used for task status)
      )
    """
    report = []
    summary = 'No saved credentials found'
    priority = Priority.LOW

    if creds:
      priority = Priority.MEDIUM
      summary = f'{len(creds)} saved credentials found in Chrome Login Data'
      report.insert(0, fmt.heading4(fmt.bold(summary)))
      report.append(fmt.bullet(fmt.bold('Credentials:')))

    for k, v in creds.items():
      line = f"Site '{k}' with users '{v}'"
      report.append(fmt.bullet(line, level=2))

    report = '\n'.join(report)
    return report, priority, summary

  @staticmethod
  def _extract_chrome_creds(filepath):
    """Extract saved credentials from a Chrome Login Database file.
    
    Args:
      filepath (str): path to Login Database file.

    Returns:
      dict: of username against website
    """
    ret = {}

    con = sqlite3.connect(filepath)
    cur = con.cursor()
    try:
      for row in cur.execute('SELECT origin_url, username_value FROM logins'):
        if not row[1]:
          continue
        if row[0] not in ret:
          ret[row[0]] = []
        ret[row[0]].append(row[1])
    # Database path not found.
    except sqlite3.OperationalError:
      return ret
    # Not a valid SQLite DB.
    except sqlite3.DatabaseError:
      return ret

    con.close()
    return ret
