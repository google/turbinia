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

from turbinia.lib.dfvfs_classes import UnattendedVolumeScannerMediator

log = logging.getLogger('turbinia')


def Enumerate(evidence):
  """Uses dfVFS to enumerate partitions in a disk / image.

  Args:
    evidence: Evidence object to be scanned.

  Raises:
    dfVFS.ScannerError if source evidence can't be scanned.

  Returns:
    list[dfVFS.path_spec]: path specs for identified partitions
  """
  dfvfs_definitions.PREFERRED_GPT_BACK_END = (
      dfvfs_definitions.TYPE_INDICATOR_GPT)
  mediator = UnattendedVolumeScannerMediator()
  mediator.credentials = evidence.credentials
  path_specs = []
  try:
    scanner = volume_scanner.VolumeScanner(mediator=mediator)
    path_specs = scanner.GetBasePathSpecs(evidence.local_path)
  except dfvfs_errors.ScannerError as e:
    raise e

  return path_specs


def GetPathSpecByLocation(path_specs, location):
  """Finds a path_spec from a list of path_specs for a given location.

  Args:
    path_specs (list[dfVFS.path_spec]): List of path_specs from volume scanner.
    location (str): dfVFS location to search for.

  Returns:
    dfVFS.path_spec for the given location or None if not found.
  """
  for path_spec in path_specs:
    child_path_spec = path_spec
    fs_location = getattr(path_spec, 'location', None)
    while path_spec.HasParent():
      type_indicator = path_spec.type_indicator
      if type_indicator in (dfvfs_definitions.TYPE_INDICATOR_TSK_PARTITION,
                            dfvfs_definitions.TYPE_INDICATOR_GPT):
        if fs_location in ('\\', '/'):
          fs_location = getattr(path_spec, 'location', None)
        break
      path_spec = path_spec.parent
    if fs_location == location:
      return child_path_spec
  return None
