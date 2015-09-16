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

# Builds bulk extractor inside a docker container along with all of its dependencies.
# Also takes care of installing requirements for Turbinia.
# Finally strips and dockerizes all binaries.

#Fetch and unpack prereqs:
#export LD_LIBRARY_PATH=/lib:/usr/lib:/usr/local/lib && \

cd /build && \
#ldconfig /usr/local/lib \
#wget http://digitalcorpora.org/downloads/afflib/afflib-3.7.4.tar.gz && \
wget http://digitalcorpora.org/downloads/hashdb/bulk_extractor-1.5.5-dev.tar.gz && \
wget http://digitalcorpora.org/downloads/hashdb/hashdb-2.0.1.tar.gz && \
git clone --recursive https://github.com/larsks/dockerize.git && \
git clone --recursive https://github.com/jonstewart/liblightgrep.git && \
wget https://53efc0a7187d0baa489ee347026b8278fe4020f6.googledrive.com/host/0B3fBvzttpiiSMTdoaVExWWNsRjg/libewf-experimental-20140608.tar.gz && \
#tar xzf afflib-3.7.4.tar.gz && \
wget https://downloads.egenix.com/python/install-pyrun && \
tar xzf bulk_extractor-1.5.5-dev.tar.gz && tar xzf hashdb-2.0.1.tar.gz && tar xzf libewf-experimental-20140608.tar.gz

# Build prereqs:
#cd /build/afflib-3.7.4 && ./configure --prefix=/usr/local && ./configure && make && make install && \
cd /build/libewf-20140608 && ./configure --prefix=/usr && make && make install && \
cd /build/hashdb-2.0.1 && ./configure --prefix=/usr && make && make install && \
cd /build/liblightgrep && ./bootstrap.sh && \
./configure --with-boost-chrono=no --with-boost-thread=no --with-boost-program-options=no --with-boost-system=no --prefix=/usr && make && make install && \

# Build bulk_extractor
cd /build/bulk_extractor-1.5.5-dev && ./configure --enable-lightgrep --prefix=/usr/local && make && make install && \

# Install mostly-static small python
cd /build && /bin/bash install-pyrun -r requirements.txt /usr/local && cd /build/dockerize && python setup.py install && \

# rsync everything important to the /out dir:
mkdir -p /out/usr/local && rsync -a /usr/local/lib/* /out/usr/local/lib && \
rsync -a /usr/local/share/* /out/usr/local/share && \

# Profile binaries, copying required shared libs. Way easier than building static libs for everything:
dockerize -n --verbose --filetools --symlinks preserve --entrypoint '/usr/local/bin/celery -A turbinia worker --loglevel=info -c 1 -Q be-worker' -o /out \
 /usr/lib/x86_64-linux-gnu/libffi* /lib/x86_64-linux-gnu/librt* /usr/lib/x86_64-linux-gnu/openssl-1.0.0/engines/* \
 /bin/bash /usr/bin/nslookup /usr/local/bin/celery /usr/local/bin/pyrun2.7 /usr/local/bin/pyrun /usr/local/bin/python \
 /usr/local/bin/bulk_extractor /usr/local/bin/turbiniactl /usr/bin/sqlite3 /usr/bin/find /usr/bin/xargs /bin/readlink /usr/bin/dirname  && \

cd /out/bin && ln -s bash sh && \

# Strip all this to make it smaller:
find /out -type f -exec strip {} \; && chmod -R 0755 /out
