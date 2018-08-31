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
"""TODO"""

from __future__ import unicode_literals

from turbinia.evidence import ReportText
from turbinia.lib.utils import extract_artifacts
from turbinia.workers import TurbiniaTask


class GKEHadoopTask(TurbiniaTask):
  """ TODO """


  def _AnalyzeHadoopAppRoot(self, collected_artifacts):
    """TODO"""
    for filepath in collected_artifacts:




  def run(self, evidence, result):
    """TODO

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
      collected_artifacts = extract_artifacts(
        artifact_names=['HadoopAppRoot'],
        disk_path=evidence.local_path,
        output_dir=os.path.join(self.output_dir, 'artifacts')
      )
    except RuntimeError as e:
      result.close(self, success=False, status=str(e))
      return result

    findings = self._AnalyzeHadoopAppRoot(collected_artifacts)

    # Write the report to the output file.
    with open(output_file_path, 'w') as fh:
      fh.write(output_evidence.text_data.encode('utf8'))
      fh.write('\n'.encode('utf8'))

    result.add_evidence(output_evidence, evidence.config)
    result.close(self, success=True)
    return result
