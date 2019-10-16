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
"""Task to extract binary files from an evidence object provided."""

from __future__ import unicode_literals

import logging
import json
import os


from turbinia import config
from turbinia.workers import TurbiniaTask
from turbinia.evidence import BinaryExtraction


class BinaryExtractorTask(TurbiniaTask):
  """Extract binaries out of evidence and provide JSON file with hashes."""

  def run(self, evidence, result):
    """Task that extracts binaries with image_export.py.

    Args:
        evidence (Evidence object):  The evidence we will process.
        result (TurbiniaTaskResult): The object to place task results into.

    Returns:
        TurbiniaTaskResult object.
    """

    config.LoadConfig()
    binary_extraction_evidence = BinaryExtraction()

    binary_extraction_evidence.local_path = self.output_dir
    image_export_log = os.path.join(
        self.output_dir, 'binary_extraction.log')

    binary_extraction_dir = os.path.join(self.output_dir, 'extracted_binaries')

    cmd = [
        'image_export.py', '--partitions', 'all', '--no_vss', '--signatures',
        'elf,exe_mz', '--logfile', image_export_log
    ]
    if config.DEBUG_TASKS:
      cmd.append('-d')
    cmd.extend(['-w', binary_extraction_dir, evidence.local_path])

    result.log('Running image_export as [{0:s}]'.format(' '.join(cmd)))

    self.execute(
        cmd, result, log_files=[image_export_log],
        new_evidence=[binary_extraction_evidence], close=True)

    json_path = os.path.join(self.output_dir, 'extracted_binaries',
                             'hashes.json')

    with open(json_path) as json_file:
      hashes = json.load(json_file)

    files = next(os.walk(binary_extraction_dir))[2]
    hash_cnt = len(hashes)
    binary_cnt = len(files)-1

    result.status = 'Extracted {0:d} hashes and {1:d} binaries from the ' \
                    'evidence.'.format(hash_cnt, binary_cnt)

    if hash_cnt != binary_cnt:
      result.log('Number of extracted binaries is not equal to the number '
                 'of extracted hashes. This might indicate issues with '
                 'image_export.py. Check binary_extraction.log for more '
                 'details.', logging.WARNING)

    binary_extraction_evidence.compress()

    return result
