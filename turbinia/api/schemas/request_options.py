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
"""Turbinia API server request options model and methods."""

from typing import Optional, List
from pydantic import BaseModel, Field


class BaseRequestOptions(BaseModel):
  """Base Request Options class to be extended by other option types. """
  name: str = None
  source_path: str = None
  recipe_name: Optional[str] = None
  jobs_allowlist: Optional[List[str]] = None
  jobs_denylist: Optional[List[str]] = None
  filter_patterns: Optional[List[str]] = None
  yara_rules: Optional[str] = None
  sketch_id: Optional[int] = None


class GoogleCloudOptions(BaseRequestOptions):
  """Google Cloud disk evidence options."""
  description: Optional[str] = 'GoogleCloudJob Evidence Options'
  project: str = None
  zone: str = None
  disk_name: str = None
  mount_partition: Optional[int] = Field(ge=0)


class GoogleCloudDiskEmbeddedOptions(GoogleCloudOptions):
  """Google CLoud jobs that work with disk images."""
  description: Optional[str] = 'GoogleCloudDiskEmbeddedJob Evidence Options'
  embedded_path: str = None
