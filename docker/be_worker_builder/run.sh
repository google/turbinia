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

# Cleans up build directories for intermediate be-worker builder containers
# Creates a small build environment container for bulk_extractor
# Generates Dockerfile/directory structure for minimal bulk_extractor/turbinia container
# Tags & pushes this container to our registry

readonly DOCKER="/usr/bin/docker --"

# Delete the old builder container:
${DOCKER} rm -f be-builder:latest 2>/dev/null

# Delete the old output dir:
sudo rm -rf out && mkdir -p out/usr/local/bin && cp be_* out/usr/local/bin/
set -ve

# Creating a hear-Dockerfile, adds our build essentials to the minimal ubuntu image:
${DOCKER} build -t be-builder:latest - <<EOF
FROM ubuntu-essential
MAINTAINER Cory Altheide "coryaltheide@gmail.com"
RUN apt-get update && apt-get install -y tar git libncurses5-dev pkg-config libtool libtre-dev libssl-dev libssl1.0.0 libxml2-dev libicu-dev flex zlib1g-dev libsqlite3-dev libbz2-dev autoconf libboost1.54-dev clang make bison libxml2 libtre5 libicu52 libsqlite3-0 wget rsync sqlite3 findutils coreutils dnsutils
ENTRYPOINT ["/build/build.sh"]
EOF

# Run the builder, which dumps a root file structure & Dockerfile into /out:
${DOCKER} run --rm -i -v "$PWD/out:/out" -v "$PWD/build:/build" be-builder:latest
cd out

# Build the minimal container:
${DOCKER} build -t be-worker-v2:latest .

# Push to the registry
${DOCKER} push be-worker-v2:latest
