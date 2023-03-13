# -*- coding: utf-8 -*-
# Copyright 2023 Google Inc.
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
"""A class to store analyzer output"""

import json
import logging

from turbinia import TurbiniaException

log = logging.getLogger('turbinia')


class AnalyzerOutput:
  """A class to record analyzer output."""

  def __init__(self, analyzer_id: str, analyzer_name: str):
    self.platform = 'turbinia'
    self.analyzer_identifier = analyzer_id
    self.analyzer_name = analyzer_name
    self.result_status = 'Success'
    self.dfiq_question_id = ''
    self.dfiq_question_conclusion = ''
    self.result_priority = 'LOW'
    self.result_summary = ''
    self.result_markdown = ''
    self.references = []
    self.attributes = []

  def validate(self):
    """Validates the analyzer output and raises exception."""
    if not self.analyzer_identifier:
      raise TurbiniaException('analyzer identifier is empty')

    if not self.analyzer_name:
      raise TurbiniaException('analyzer name is empty')

    if self.result_status.lower() not in ['success', 'failed']:
      raise TurbiniaException('unknown result status {self.result_status}')

    if self.result_priority.upper() not in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW',
                                            'INFO']:
      raise TurbiniaException(
          'unknown result priority valude {self.result_priority}')

    if not self.result_summary:
      raise TurbiniaException('result summary is empty')
