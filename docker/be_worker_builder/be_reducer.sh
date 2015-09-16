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

# This script takes one argument, job_id. This is the turbinia job_id. It is not
# intended to be run manually by a human, but invoked from turbinia.

readonly JOB_ID="$1"
readonly TMP_DIR="/tmp"

find "${TMP_DIR}"/"${JOB_ID}" -name report.sqlite | \
    xargs -I {} sqlite3 {} .dump | \
    sqlite3 "${TMP_DIR}"/"${JOB_ID}"/full_report.sqlite 2>/dev/null
sqlite3 "${TMP_DIR}"/"${JOB_ID}"/full_report.sqlite REINDEX
