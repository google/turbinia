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
"""Turbinia Request schema class."""

from typing import Optional, Dict, Any
from pydantic import BaseModel
from turbinia.api.schemas import request_options


class Request(BaseModel):
  """Base request object. """
  description: Optional[str] = 'Turbinia request object'
  evidence: Dict[Any, Any]
  request_options: request_options.BaseRequestOptions
