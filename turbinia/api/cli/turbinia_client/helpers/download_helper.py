#!/usr/bin/env python
#
# Copyright 2024 Google Inc.
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
"""Methods for downloading content via the API client"""

import logging

from turbinia_api_lib.rest import RESTResponseType
from tqdm.auto import tqdm

log = logging.getLogger(__name__)


def download_with_progressbar(
    api_response: RESTResponseType, filename: str) -> None:
  """Download the response and save into a local file."""
  try:
    with open(filename, 'wb') as file:
      with tqdm(
          # all optional kwargs
          unit='B',
          unit_scale=True,
          unit_divisor=1024,
          miniters=1,
          desc=filename,
          total=int(api_response.headers.get('content-length', 0))) as pbar:
        for chunk in api_response.read_chunked():
          file.write(chunk)
          pbar.update(len(chunk))
  except OSError as exception:
    log.error(f'Unable to save file: {exception}')
