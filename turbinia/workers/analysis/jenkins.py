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
"""Task for analysing Jenkins."""

from __future__ import unicode_literals

import os

from turbinia.evidence import ReportText
from turbinia.workers import TurbiniaTask
from turbinia.lib.utils import get_artifacts


class JenkinsAnalysisTask(TurbiniaTask):
  """Task to analyze a Jenkins install."""

  def run(self, evidence, result):
    """Run the Jenkins worker.

    Args:
        evidence (Evidence object):  The evidence to process
        result (TurbiniaTaskResult): The object to place task results into.

    Returns:
        TurbiniaTaskResult object.
    """
    # What type of evidence we should output.
    output_evidence = ReportText()

    # Where to store the resulting output file.
    output_file_name = 'jenkins_analysis.txt'
    output_file_path = os.path.join(self.output_dir, output_file_name)

    # Set the output file as the data source for the output evidence.
    output_evidence.local_path = output_file_path

    # TODO(jberggren) Create Jenkins artifact and use that.
    collected_files = get_artifacts(
      artifact_names=['GlobalShellConfigs'],
      disk_path=evidence.local_path,
      output_dir=os.path.join(self.output_dir, 'artifacts')
    )

    # Populate the text_data attribute so anyone who picks up this evidence
    # doesn't have to fetch and read the file again.
    # TODO(jberggren) Write actual analysis logic.
    output_evidence.text_data = '\n'.join(collected_files)

    # Write the report to the output file.
    with open(output_file_path, 'w') as fh:
      fh.write(output_evidence.text_data.encode('utf8'))

    # Add the resulting evidence to the result object.
    result.add_evidence(output_evidence, evidence.config)
    result.close(self, success=True)

    return result


