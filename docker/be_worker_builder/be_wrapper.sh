#!/bin/bash
#
# Copyright 2015 Google Inc.
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

# This script is not intended to be run manually by a human, but invoked from
# turbinia. The scripts takes four arguments. The source data path, temporary
# output path, calculated offsets and turbinia job_id.

readonly IMAGE_PATH="$1"
readonly OUTPUT_PATH="$2"
readonly OFFSETS="$3"
readonly JOB_ID="$4"
readonly BULK_EXTRACTOR="/usr/local/bin/bulk_extractor"

${BULK_EXTRACTOR} -o "${OUTPUT_PATH}" -S write_feature_sqlite3=yes -Y \
    "${OFFSETS}" "${IMAGE_PATH}"
