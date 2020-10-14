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

import logging
import os

from dfvfs.helpers import source_scanner
from dfvfs.lib import errors as dfvfs_errors
from dfvfs.lib import definitions as dfvfs_definitions
from dfvfs.volume import apfs_volume_system
from dfvfs.volume import tsk_volume_system


class SourceAnalyzer(object):
  """Analyzer to scan for volumes."""

  def __init__(self):
    """Initializes a source analyzer."""
    super(SourceAnalyzer, self).__init__()
    self._log = logging.getLogger('turbinia')
    self._source_path_specs = []
    self._source_scanner = source_scanner.SourceScanner()

  def _GetVolumeIdentifiers(self, scan_node, volume_type):
    """Determines the volume identifiers.

    Args:
      scan_node (dfvfs.SourceScanNode): scan node.
      volume_type (str): type of volume.

    Returns:
      list[str]: Normalized volume identifiers.

    Raises:
      RuntimeError: if the format of or within the source is not supported or
          the the scan node is invalid.
    """
    if not scan_node or not scan_node.path_spec:
      raise RuntimeError('Invalid scan node.')

    prefix = None
    if volume_type == dfvfs_definitions.TYPE_INDICATOR_APFS_CONTAINER:
      volume_system = apfs_volume_system.APFSVolumeSystem()
      prefix = 'apfs'
    elif volume_type == dfvfs_definitions.TYPE_INDICATOR_TSK_PARTITION:
      volume_system = tsk_volume_system.TSKVolumeSystem()
      prefix = 'p'
    else:
      raise RuntimeError('Invalid volume type: {0!s}'.format(volume_type))
    volume_system.Open(scan_node.path_spec)

    volume_identifiers = self._source_scanner.GetVolumeIdentifiers(
        volume_system)
    if not volume_identifiers:
      return []

    volumes = range(1, volume_system.number_of_volumes + 1)

    return self._NormalizedVolumeIdentifiers(
        volume_system, volumes, prefix=prefix)

  def _NormalizedVolumeIdentifiers(
      self, volume_system, volume_identifiers, prefix='v'):
    """Normalizes volume identifiers.

    Args:
      volume_system (VolumeSystem): volume system.
      volume_identifiers (list[int|str]): allowed volume identifiers, formatted
          as an integer or string with prefix.
      prefix (Optional[str]): volume identifier prefix.

    Returns:
      list[str]: volume identifiers with prefix.

    Raises:
      RuntimeError: if the volume identifier is not supported or no volume could
          be found that corresponds with the identifier.
    """
    normalized_volume_identifiers = []
    for volume_identifier in volume_identifiers:
      if isinstance(volume_identifier, int):
        volume_identifier = '{0:s}{1:d}'.format(prefix, volume_identifier)

      elif not volume_identifier.startswith(prefix):
        try:
          volume_identifier = int(volume_identifier, 10)
          volume_identifier = '{0:s}{1:d}'.format(prefix, volume_identifier)
        except (TypeError, ValueError):
          pass

      try:
        volume = volume_system.GetVolumeByIdentifier(volume_identifier)
      except KeyError:
        volume = None

      if not volume:
        raise RuntimeError(
            'Volume missing for identifier: {0:s}.'.format(volume_identifier))

      normalized_volume_identifiers.append(volume_identifier)

    return normalized_volume_identifiers

  def _ScanFileSystem(self, scan_node, base_path_specs):
    """Scans a file system scan node for file systems.

    Args:
      scan_node (SourceScanNode): file system scan node.
      base_path_specs (list[PathSpec]): file system base path specifications.

    Raises:
      RuntimeError: if the scan node is invalid.
    """
    if not scan_node or not scan_node.path_spec:
      raise RuntimeError('Invalid or missing file system scan node.')

    base_path_specs.append(scan_node.path_spec)

  def _ScanVolume(self, scan_context, scan_node, base_path_specs):
    """Scans a volume scan node for volume and file systems.

    Scans recursively and adds a path spec to base_path_specs for each volume
    identified.

    Args:
      scan_context (SourceScannerContext): source scanner context.
      scan_node (SourceScanNode): volume scan node.
      base_path_specs (list[PathSpec]): file system base path specifications.

    Raises:
      RuntimeError: if the format of or within the source is not supported or
          the scan node is invalid.
    """
    if not scan_node or not scan_node.path_spec:
      raise RuntimeError('Invalid or missing scan node.')

    if scan_context.IsLockedScanNode(scan_node.path_spec):
      # TODO: Add encrypted volume support
      self._log.info(
          'Identified an unsupported locked volume: {0!s}'.format(
              scan_node.path_spec.CopyToDict()))
      return

    if scan_node.IsVolumeSystemRoot():
      self._ScanVolumeSystemRoot(scan_context, scan_node, base_path_specs)

    elif scan_node.IsFileSystem():
      self._ScanFileSystem(scan_node, base_path_specs)

    elif scan_node.type_indicator == dfvfs_definitions.TYPE_INDICATOR_VSHADOW:
      # TODO: Add volume shadow support
      self._log.info(
          'Identified an unsupported volume shadow: {0!s}'.format(
              scan_node.path_spec.CopyToDict()))
      return

    else:
      for sub_scan_node in scan_node.sub_nodes:
        self._ScanVolume(scan_context, sub_scan_node, base_path_specs)

  def _ScanVolumeSystemRoot(self, scan_context, scan_node, base_path_specs):
    """Scans a volume system root scan node for volume and file systems.

    Adds a base path spec for each volume identified.

    Args:
      scan_context (SourceScannerContext): source scanner context.
      scan_node (SourceScanNode): volume system root scan node.
      base_path_specs (list[PathSpec]): file system base path specifications.

    Raises:
      RuntimeError: if the scan node is invalid, the scan node type is not
          supported or if a sub scan node cannot be retrieved.
    """
    if not scan_node or not scan_node.path_spec:
      raise RuntimeError('Invalid scan node.')

    if scan_node.type_indicator == (
        dfvfs_definitions.TYPE_INDICATOR_APFS_CONTAINER):
      volume_identifiers = self._GetVolumeIdentifiers(
          scan_node, scan_node.type_indicator)

    elif scan_node.type_indicator == dfvfs_definitions.TYPE_INDICATOR_VSHADOW:
      # TODO: Add volume shadow support
      self._log.info(
          'Identified an unsupported volume shadow: {0!s}'.format(
              scan_node.path_spec.CopyToDict()))
      volume_identifiers = []

    else:
      raise RuntimeError(
          'Unsupported volume system type: {0:s}.'.format(
              scan_node.type_indicator))

    for volume_identifier in volume_identifiers:
      location = '/{0:s}'.format(volume_identifier)
      sub_scan_node = scan_node.GetSubNodeByLocation(location)
      if not sub_scan_node:
        raise RuntimeError(
            'Scan node missing for volume identifier: {0:s}.'.format(
                volume_identifier))

      self._ScanVolume(scan_context, sub_scan_node, base_path_specs)

  def ScanSource(self, source_path):
    """Scans the source path for volume and file systems.

    Args:
      source_path (str): the source path.

    Returns:
      List of path specs.

    Raises:
      RuntimeError: if the source path does not exist, or if the source path is
          not a file, or if the format of or within the source file is not
          supported.
    """
    if not os.path.exists(source_path):
      raise RuntimeError('No such source: {0:s}.'.format(source_path))

    scan_context = source_scanner.SourceScannerContext()
    scan_context.OpenSourcePath(source_path)

    try:
      self._source_scanner.Scan(scan_context)
    except (ValueError, dfvfs_errors.BackEndError) as exception:
      raise RuntimeError(
          'Unable to scan source [{0:s}] with error: {1!s}.'.format(
              source_path, exception))

    # This method may also be called for files / directories
    if scan_context.source_type not in (
        scan_context.SOURCE_TYPE_STORAGE_MEDIA_DEVICE,
        scan_context.SOURCE_TYPE_STORAGE_MEDIA_IMAGE):
      scan_node = scan_context.GetRootScanNode()
      self._source_path_specs.append(scan_node.path_spec)
      return self._source_path_specs

    scan_node = scan_context.GetRootScanNode()
    while len(scan_node.sub_nodes) == 1:
      scan_node = scan_node.sub_nodes[0]

    base_path_specs = []
    if scan_node.type_indicator != (
        dfvfs_definitions.TYPE_INDICATOR_TSK_PARTITION):
      self._ScanVolume(scan_context, scan_node, base_path_specs)

    else:
      partition_identifiers = self._GetVolumeIdentifiers(
          scan_node, scan_node.type_indicator)
      if not partition_identifiers:
        raise RuntimeError('No partitions found.')

      for partition_identifier in partition_identifiers:
        location = '/{0:s}'.format(partition_identifier)
        sub_scan_node = scan_node.GetSubNodeByLocation(location)
        self._ScanVolume(scan_context, sub_scan_node, base_path_specs)

    if not base_path_specs:
      raise RuntimeError('No supported file system found in source.')

    self._source_path_specs = base_path_specs

    return self._source_path_specs
