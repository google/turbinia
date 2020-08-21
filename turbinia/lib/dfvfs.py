# -*- coding: utf-8 -*-
# Copyright 2020 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Classes for dfVFS"""

import os

from dfvfs.helpers import source_scanner
from dfvfs.lib import definitions


class SourceAnalyzer(object):
  """Analyzer to scan for volumes."""

  # Class constant that defines the default read buffer size.
  _READ_BUFFER_SIZE = 32768

  def __init__(self, auto_recurse=True):
    """Initializes a source analyzer."""
    super(SourceAnalyzer, self).__init__()
    self._auto_recurse = auto_recurse
    self._source_scanner = source_scanner.SourceScanner()

  def Analyze(self, source_path, result):
    """Analyzes the source.
    Args:
      source_path (str): the source path.
      result (TurbiniaTaskResult): The object to place task results into.
    Raises:
      RuntimeError: if the source path does not exist, or if the source path
          is not a file or directory, or if the format of or within the source
          file is not supported.
    """
    if not os.path.exists(source_path):
      raise RuntimeError('No such source: {0:s}.'.format(source_path))

    scan_context = source_scanner.SourceScannerContext()
    scan_path_spec = None
    scan_step = 0

    scan_context.OpenSourcePath(source_path)

    while True:
      self._source_scanner.Scan(
          scan_context, auto_recurse=self._auto_recurse,
          scan_path_spec=scan_path_spec)

      if not scan_context.updated:
        break

      if not self._auto_recurse:
        scan_node = scan_context.GetRootScanNode()

        if not scan_node:
          return

        location = getattr(scan_node.path_spec, 'location', None)
        if location is not None:
          start_offset = getattr(scan_node.path_spec, 'start_offset', None)
          if start_offset is not None:
            result.log('{0:s} offset: {1:d}'.format(location, start_offset))

      scan_step += 1

      # The source is a directory or file.
      if scan_context.source_type in [
          definitions.SOURCE_TYPE_DIRECTORY, definitions.SOURCE_TYPE_FILE]:
        break

      # TODO: Add support for encrypted volumes

      if not self._auto_recurse:
        scan_node = scan_context.GetUnscannedScanNode()
        if not scan_node:
          return
        scan_path_spec = scan_node.path_spec

    if self._auto_recurse:
      scan_node = scan_context.GetRootScanNode()

      if not scan_node:
        return

      location = getattr(scan_node.path_spec, 'location', None)
      if location is not None:
        start_offset = getattr(scan_node.path_spec, 'start_offset', None)
        if start_offset is not None:
          result.log('{0:s} offset: {1:d}'.format(location, start_offset))
