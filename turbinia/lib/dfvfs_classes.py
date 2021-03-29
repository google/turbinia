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

from dfvfs.helpers import volume_scanner
from dfvfs.lib import definitions as dfvfs_definitions


class UnattendedVolumeScannerMediator(volume_scanner.VolumeScannerMediator):
  """Unattended volume scanner mediator."""

  def __init__(self):
    """Initializes an unattended volume scanner mediator."""
    super(UnattendedVolumeScannerMediator, self).__init__()
    self._log = logging.getLogger('turbinia')
    self.credentials = []

  def GetAPFSVolumeIdentifiers(self, volume_system, volume_identifiers):
    """Retrieves APFS volume identifiers.

    In an unattended execution, this method returns all volume identifiers.

    Args:
      volume_system (APFSVolumeSystem): volume system.
      volume_identifiers (list[str]): volume identifiers including prefix.

    Returns:
      list[str]: all volume identifiers including prefix.
    """
    prefix = 'apfs'
    return [
        '{0:s}{1:d}'.format(prefix, volume_index)
        for volume_index in range(1, volume_system.number_of_volumes + 1)
    ]

  def GetLVMVolumeIdentifiers(self, volume_system, volume_identifiers):
    """Retrieves LVM volume identifiers.

    This method can be used to prompt the user to provide LVM volume
    identifiers.

    Args:
      volume_system (LVMVolumeSystem): volume system.
      volume_identifiers (list[str]): volume identifiers including prefix.

    Returns:
      list[str]: selected volume identifiers including prefix or None.
    """
    prefix = 'lvm'
    return [
        '{0:s}{1:d}'.format(prefix, volume_index)
        for volume_index in range(1, volume_system.number_of_volumes + 1)
    ]

  def GetPartitionIdentifiers(self, volume_system, volume_identifiers):
    """Retrieves partition identifiers.

    In an unattended execution, this method returns all partition identifiers.

    Args:
      volume_system (TSKVolumeSystem): volume system.
      volume_identifiers (list[str]): volume identifiers including prefix.

    Returns:
      list[str]: all volume identifiers including prefix.
    """
    prefix = 'p'
    return [
        '{0:s}{1:d}'.format(prefix, volume_index)
        for volume_index in range(1, volume_system.number_of_volumes + 1)
    ]

  def GetVSSStoreIdentifiers(self, volume_system, volume_identifiers):
    """Retrieves VSS store identifiers.

    Placeholder method for VSS support.

    Args:
      volume_system (VShadowVolumeSystem): volume system.
      volume_identifiers (list[str]): volume identifiers including prefix.

    Returns:
      list[str]: None (until VSS support is added).
    """
    self._log.info(
        'Volume shadows are currently unsupported: {0!s}'.format(
            volume_identifiers))
    return []

  def UnlockEncryptedVolume(
      self, source_scanner_object, scan_context, locked_scan_node, credentials):
    """Unlocks an encrypted volume.

    Placeholder method for encrypted volume support.

    Args:
      source_scanner_object (SourceScanner): source scanner.
      scan_context (SourceScannerContext): source scanner context.
      locked_scan_node (SourceScanNode): locked scan node.
      credentials (Credentials): credentials supported by the locked scan node.

    Returns:
      bool: True if the volume was unlocked.
    """
    if locked_scan_node.type_indicator == dfvfs_definitions.TYPE_INDICATOR_BDE:
      self._log.info('Found a BitLocker encrypted volume.')
    else:
      self._log.info(
          'Encrypted {0!s} volume not currently supported: {1!s}'.format(
              locked_scan_node.path_spec.type_indicator,
              locked_scan_node.path_spec.CopyToDict()))
      return False

    result = False

    for credential in self.credentials:
      credential_type = credential['credential_type']
      credential_data = credential['credential_data']
      try:
        result = source_scanner_object.Unlock(
            scan_context, locked_scan_node.path_spec, credential_type,
            credential_data)
        if result:
          self._log.info('Encrypted volume unlocked.')
          break
      except KeyError as e:
        self._log.warning('Unable to unlock volume: {0!s}'.format(e))

    if not result:
      self._log.warning('Unable to unlock volume.')
    return result
