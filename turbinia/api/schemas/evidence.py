# -*- coding: utf-8 -*-
# Copyright 2022 Google Inc.
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
"""Turbinia Evidence schema class."""

import json

from typing import Optional
from pydantic import BaseModel, validator

from turbinia import evidence

#TODO(IGORMR) add nested classes for each type


class Evidence(BaseModel):
  """Base evidence object"""
  file_name: str
  evidence_type: str
  new_name: Optional[str] = None
  browser_type: Optional[str] = None
  disk_name: Optional[str] = None
  embedded_path: Optional[str] = None
  format: Optional[str] = None
  mount_partition: Optional[str] = None
  name: Optional[str] = None
  profile: Optional[str] = None
  project: Optional[str] = None
  source: Optional[str] = None
  zone: Optional[str] = None

  @classmethod
  def __get_validators__(cls):
    yield cls.validate_to_json

  @classmethod
  def validate_to_json(cls, value):
    """Converts the multiple json inputs to a list[EvidenceInformation]"""
    if isinstance(value, str):
      entries = value.split('},')
      information = {}
      for entry in entries:
        if entry[-1] != '}':
          entry = entry + '}'
        evidence_info = cls(**json.loads(entry))
        if not evidence_info.new_name or evidence_info.new_name == 'string':
          evidence_info.new_name = evidence_info.file_name
        # Uses the file name (without extension) as the key to get the evidence
        information[evidence_info.file_name] = evidence_info
      return information

  @validator('evidence_type')
  @classmethod
  def check_evidence_type(cls, value):
    if value not in (evidence.map_evidence_attributes().keys()):
      raise ValueError(f'{value:s} is not an evidence type.')
    return value
