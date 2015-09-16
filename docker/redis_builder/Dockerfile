#!/bin/bash
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

FROM gliderlabs/alpine:3.1
MAINTAINER Cory Altheide "coryaltheide@gmail.com"
ADD Dockerfile.run /Dockerfile
RUN apk --update add redis && chown redis /var/lib/redis && chmod +x /var/lib/redis
CMD tar -cf - /Dockerfile /etc/passwd /var/lib/redis /etc/group /usr/bin/redis-server /lib/ld-musl-x86_64.so.1 /lib/libc.musl-x86_64.so.1
