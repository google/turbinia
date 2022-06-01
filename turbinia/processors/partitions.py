# -*- coding: utf-8 -*-
# Copyright 2021 Google LLC
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
"""Evidence processor to enumerate partitions."""

import logging

from dfvfs.helpers import volume_scanner
from dfvfs.lib import definitions as dfvfs_definitions
from dfvfs.lib import errors as dfvfs_errors

from turbinia import TurbiniaException

log = logging.getLogger('turbinia')


def Enumerate(evidence, location=None):
  """Uses dfVFS to enumerate partitions in a disk / image.

  Args:
    evidence: Evidence object to be scanned.
    location: dfVFS partition location to be scanned

  Raises:
    TurbiniaException if source evidence can't be scanned.

  Returns:
    list[dfVFS.path_spec]: path specs for identified partitions
  """
  options = volume_scanner.VolumeScannerOptions()
  options.partitions = ['all']
  options.volumes = ['all']
  if location:
    log.debug(
        'Scanning {0:s} for partition at location {1!s}'.format(
            evidence.name, location))
    # APFS and LVM are volumes rather than partitions.
    if location.find('apfs') != -1 or location.find('lvm') != -1:
      options.volumes = [location.replace('/', '')]
    elif location in ('/', '\\'):
      options.partitions = [location]
    else:
      options.partitions = [location.replace('/', '')]
  # Not processing volume snapshots
  options.snapshots = ['none']
  options.credentials = evidence.credentials

  path_specs = []
  try:
    # Setting the volume scanner mediator to None will cause the volume scanner
    # to operate in unattended mode
    scanner = volume_scanner.VolumeScanner(mediator=None)
    path_specs = scanner.GetBasePathSpecs(evidence.local_path, options=options)
  except dfvfs_errors.ScannerError as e:
    raise TurbiniaException(
        'Could not enumerate partitions [{0!s}]: {1!s}'.format(
            evidence.local_path, e))

  return path_specs


def GetPartitionEncryptionType(path_spec):
  """Checks a partition for encryption.

  Args:
    path_spec (dfVFS.path_spec): Partition path_spec.

  Returns:
    String representing the type of encryption, or None.
  """
  encryption_type = None

  if not path_spec or not path_spec.HasParent():
    return None

  if path_spec.parent.type_indicator == dfvfs_definitions.TYPE_INDICATOR_BDE:
    encryption_type = 'BDE'
  return encryption_type
