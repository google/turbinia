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
from dfvfs.lib import errors as dfvfs_errors
from dfvfs.lib import definitions as dfvfs_definitions
from dfvfs.volume import apfs_volume_system
from dfvfs.volume import tsk_volume_system


class SourceAnalyzer(object):
  """Analyzer to scan for volumes."""

  def __init__(self):
    """Initializes a source analyzer."""
    super(SourceAnalyzer, self).__init__()
    self._source_scanner = source_scanner.SourceScanner()
    self._volumes = {}

  def _GetAPFSVolumeIdentifiers(self, scan_node):
    """Determines the APFS volume identifiers.
    Args:
      scan_node (dfvfs.SourceScanNode): scan node.
    Returns:
      list[str]: APFS volume identifiers.
    """
    if not scan_node or not scan_node.path_spec:
      raise RuntimeError('Invalid scan node.')

    volume_system = apfs_volume_system.APFSVolumeSystem()
    volume_system.Open(scan_node.path_spec)

    volume_identifiers = self._source_scanner.GetVolumeIdentifiers(
        volume_system)
    if not volume_identifiers:
      return []

    volumes = range(1, volume_system.number_of_volumes + 1)

    return self._NormalizedVolumeIdentifiers(
        volume_system, volumes, prefix='apfs')

  def _GetTSKPartitionIdentifiers(self, scan_node):
    """Determines the TSK partition identifiers.
    Args:
      scan_node (dfvfs.SourceScanNode): scan node.
    Returns:
      list[str]: TSK partition identifiers.
    """
    if not scan_node or not scan_node.path_spec:
      raise RuntimeError('Invalid scan node.')

    volume_system = tsk_volume_system.TSKVolumeSystem()
    volume_system.Open(scan_node.path_spec)

    volume_identifiers = self._source_scanner.GetVolumeIdentifiers(
        volume_system)
    if not volume_identifiers:
      return []

    partitions = range(1, volume_system.number_of_volumes + 1)

    return self._NormalizedVolumeIdentifiers(
        volume_system, partitions, prefix='p')

  def _NormalizedVolumeIdentifiers(
      self, volume_system, volume_identifiers, prefix='v'):
    """Normalizes volume identifiers and collects volume extents.
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

      # TODO: Add support for more than one set of extents.
      if volume.number_of_extents != 1:
        raise RuntimeError(
            'Volume {0:s} has more than one set of extents: {1:d}'.format(
                volume_identifier, volume.number_of_extents))

      normalized_volume_identifiers.append(volume_identifier)
      description = volume.GetAttribute('description').value
      volume_extents = volume.extents[0]
      offset = volume_extents.offset
      size = volume_extents.size

      self._volumes[volume_identifier] = {
          'description': description,
          'offset': offset,
          'size': size
      }

    return normalized_volume_identifiers

  def _ScanVolume(self, scan_context, scan_node):
    """Scans a volume scan node for volume and file systems.
    Args:
      scan_context (SourceScannerContext): source scanner context.
      scan_node (SourceScanNode): volume scan node.
    Raises:
      RuntimeError: if the format of or within the source is not supported or
          the scan node is invalid.
    """
    if not scan_node or not scan_node.path_spec:
      raise RuntimeError('Invalid or missing scan node.')

    if scan_context.IsLockedScanNode(scan_node.path_spec):
      # TODO: Add encrypted volume support
      return

    if scan_node.IsVolumeSystemRoot():
      self._ScanVolumeSystemRoot(scan_context, scan_node)

    elif scan_node.type_indicator == dfvfs_definitions.TYPE_INDICATOR_VSHADOW:
      # TODO: Add volume shadow support
      return

    else:
      for sub_scan_node in scan_node.sub_nodes:
        self._ScanVolume(scan_context, sub_scan_node)

  def _ScanVolumeSystemRoot(self, scan_context, scan_node):
    """Scans a volume system root scan node for volume and file systems.
    Args:
      scan_context (SourceScannerContext): source scanner context.
      scan_node (SourceScanNode): volume system root scan node.
    Raises:
      RuntimeError: if the scan node is invalid, the scan node type is not
          supported or if a sub scan node cannot be retrieved.
    """
    if not scan_node or not scan_node.path_spec:
      raise RuntimeError('Invalid scan node.')

    if scan_node.type_indicator == (
        dfvfs_definitions.TYPE_INDICATOR_APFS_CONTAINER):
      volume_identifiers = self._GetAPFSVolumeIdentifiers(scan_node)

    elif scan_node.type_indicator == dfvfs_definitions.TYPE_INDICATOR_VSHADOW:
      # TODO: Add volume shadow support
      volume_identifiers = []

    else:
      raise RuntimeError('Unsupported volume system type: {0:s}.'.format(
          scan_node.type_indicator))

    for volume_identifier in volume_identifiers:
      location = '/{0:s}'.format(volume_identifier)
      sub_scan_node = scan_node.GetSubNodeByLocation(location)
      if not sub_scan_node:
        raise RuntimeError(
            'Scan node missing for volume identifier: {0:s}.'.format(
                volume_identifier))

      self._ScanVolume(scan_context, sub_scan_node)

  def Analyze(self, source_path):
    """Analyzes the source.
    Args:
      source_path (str): the source path.
    Returns:
      List of volume attributes and extents
    Raises:
      RuntimeError: if the source path does not exist, or if the source path is
          not a file or directory, or if the format of or within the source file
          is not supported.
    """
    if not os.path.exists(source_path):
      raise RuntimeError('No such source: {0:s}.'.format(source_path))

    scan_context = source_scanner.SourceScannerContext()
    scan_context.OpenSourcePath(source_path)

    try:
      self._source_scanner.Scan(scan_context)
    except (ValueError, dfvfs_errors.BackEndError) as exception:
      raise RuntimeError(
          'Unable to scan source with error: {0!s}.'.format(exception))

    if scan_context.source_type not in (
        scan_context.SOURCE_TYPE_STORAGE_MEDIA_DEVICE,
        scan_context.SOURCE_TYPE_STORAGE_MEDIA_IMAGE):
      return

    scan_node = scan_context.GetRootScanNode()
    while len(scan_node.sub_nodes) == 1:
      scan_node = scan_node.sub_nodes[0]

    if scan_node.type_indicator != (
        dfvfs_definitions.TYPE_INDICATOR_TSK_PARTITION):
      self._ScanVolume(scan_context, scan_node)

    else:
      partition_identifiers = self._GetTSKPartitionIdentifiers(scan_node)
      if not partition_identifiers:
        raise RuntimeError('No partitions found.')

      for partition_identifier in partition_identifiers:
        location = '/{0:s}'.format(partition_identifier)
        sub_scan_node = scan_node.GetSubNodeByLocation(location)
        self._ScanVolume(scan_context, sub_scan_node)

    return self._volumes
