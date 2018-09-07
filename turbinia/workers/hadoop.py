# -*- coding: utf-8 -*-
# Copyright 2015 Google Inc.
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
"""Task to analyse Hadoop AppRoot files."""

from __future__ import unicode_literals

from turbinia import TurbiniaException

from turbinia.evidence import ReportText
from turbinia.lib.utils import extract_artifacts
from turbinia.workers import TurbiniaTask

import os
import subprocess


class HadoopTask(TurbiniaTask):
  """Task to analyse Hadoop AppRoot files."""

  def _AnalyzeHadoopAppRoot(self, collected_artifacts):
    """Runs a naive AppRoot files parsing method.

    This extracts strings from the saved task file, and search usual
    post-compromise suspicious patterns.

    TODO: properly parse the Proto. Some documentation can be found over there:
    https://svn.apache.org/repos/asf/hadoop/common/branches/branch-0.23.7/hadoop-yarn-project/hadoop-yarn/hadoop-yarn-api/src/main/proto/yarn_protos.proto

    Args:
      collected_artifacts(list(str)): a list of paths to extracted files
    Returns:
      str: the result report.
    """
    strings_report = ''
    evil_commands = []
    for filepath in collected_artifacts:
      strings_report += 'Strings for {0}:\n'.format(filepath)
      strings = subprocess.check_output(['/usr/bin/strings', '-a', filepath])
      strings_report += strings
      for line in strings.splitlines():
        if (line.find('curl')>0) or (line.find('wget')>0):
          evil_commands.append((filepath, line))

    report = 'Extracted commands from Yarn tasks\n'
    if evil_commands:
      report += 'Found suspicious commands:\n'
    for file_path, command in evil_commands:
      report += '\tFile: {0}\n'.format(filepath)
      report += 'Command: "{0}"\n'.format(command)

    report += '\nAll strings from Yarn Tasks:\n'
    report += strings_report

    return report

  def run(self, evidence, result):
    """Run Hadoop specific analysis on the evidences.

    Args:
        evidence (Evidence object):  The evidence we will process
        result (TurbiniaTaskResult): The object to place task results into.

    Returns:
        TurbiniaTaskResult object.
    """

    # What type of evidence we should output.
    output_evidence = ReportText()

    # Where to store the resulting output file.
    output_file_name = 'hadoop_analysis.txt'
    output_file_path = os.path.join(self.output_dir, output_file_name)

    output_evidence.local_path = output_file_path

    try:
      # We don't use FileArtifactExtractionTask as it export one evidence per
      # file extracted
      collected_artifacts = extract_artifacts(
        artifact_names=['HadoopAppRoot'],
        disk_path=evidence.local_path,
        output_dir=os.path.join(self.output_dir, 'artifacts')
      )

      text_report = self._AnalyzeHadoopAppRoot(collected_artifacts)
      output_evidence.text_data = text_report

      # Write the report to the output file.
      with open(output_file_path, 'w') as fh:
        fh.write(output_evidence.text_data.encode('utf8'))
        fh.write('\n'.encode('utf8'))

      result.add_evidence(output_evidence, evidence.config)
      result.close(self, success=True)
    except TurbiniaException as e:
      result.close(self, success=False, status=str(e))
      return result
    return result
