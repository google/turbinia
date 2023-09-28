# Multi-stage build
# Use: docker build --no-cache --build-arg PPA_TRACK="[staging|stable] GOVERSION=[1.20.6|1.18|?]"

# Build 0 - fraken
FROM golang:alpine AS fraken-builder
RUN apk add --no-cache -t .build-deps \
  autoconf \
  automake \
  bison \
  build-base \
  curl \
  file \
  file-dev \
  flex \
  git \
  jansson \
  jansson-dev \
  jansson-static \
  libc-dev \
  libmagic \
  libmagic-static \
  libtool \
  linux-headers \
  openssl \
  openssl-dev \
  openssl-libs-static \
  py3-setuptools \
  python3 \
  python3-dev \
  sudo

RUN set -x \
  && echo "Compiling Yara from source..."

# Fetch and compile libyara
RUN mkdir -p /opt/fraken/yara
WORKDIR /opt/fraken/yara
RUN cd /opt/fraken/yara && curl -s -L --retry 5 "$(curl -s -L --retry 5 https://api.github.com/repos/VirusTotal/Yara/releases/latest | sed -n 's/.*"tarball_url": "\(.*\)",.*/\1/p')"  | tar -xz --strip-components=1
RUN ./bootstrap.sh
RUN sync
RUN ./configure --with-crypto \
  --enable-magic \
  --enable-cuckoo
RUN make
RUN sudo make install

# Compile fraken statically
COPY tools/fraken/* /opt/fraken/
RUN cd /opt/fraken && GOOS=linux GOARCH=amd64 go build -a -v -ldflags="-linkmode=external -extldflags=-static" -installsuffix netgo -tags yara_static,osusergo,netgo -o fraken

# Build 1 - Turbinia Worker
FROM ubuntu:22.04 AS worker-builder
ENV DEBIAN_FRONTEND=noninteractive
ENV PIP_NO_CACHE_DIR=1

ARG PPA_TRACK=stable

RUN apt-get update && apt-get -y upgrade && apt-get -y install \
    apt-transport-https \
    apt-utils \
    ca-certificates \
    curl \
    git \
    john \
    john-data \
    libleveldb1d \
    libleveldb-dev \
    libterm-readline-gnu-perl \
    lvm2 \
    pocl-opencl-icd \
    p7zip-full \
    python3-pip \
    software-properties-common \
    sudo \
    testdisk \
    wget \
    && apt-get clean && rm -rf /var/cache/apt/* /var/lib/apt/lists/*

ADD requirements.txt /tmp/
RUN cd /tmp/ && pip3 install -r requirements.txt

RUN pip3 install pip --upgrade
RUN pip3 install requests --upgrade
RUN pip3 install urllib3 cryptography --upgrade

# Install third-party dependencies
#   dfwdewey
#   pyhindsight
#   impacket
RUN pip3 install dfDewey
RUN pip3 install pyhindsight
RUN pip3 install impacket --no-deps

# Install various packages from the GIFT PPA
#   bulkextractor
#   dfImageTools
#   docker-explorer
#   libbde-tools
#   libfsapfs-tools
#   libluksde-tools
#   Plaso
#   Sleuthkit
RUN add-apt-repository -y ppa:gift/$PPA_TRACK
RUN apt-get update && apt-get -y install \
    bulk-extractor \
    dfimagetools-tools \
    docker-explorer-tools \
    libbde-tools \
    libewf \
    libewf-python3 \
    libewf-tools \
    libfsapfs-tools \
    libluksde-tools \
    plaso-tools \
    python3-dfimagetools \
    python3-dfvfs \
    python3-plaso \
    sleuthkit \
    && apt-get clean && rm -rf /var/cache/apt/* /var/lib/apt/lists/*

# Add turbinia user to system and sudoers
RUN useradd -r -s /bin/nologin -G disk,sudo -u 999 turbinia
RUN echo "turbinia ALL = (root) NOPASSWD: ALL" > /etc/sudoers.d/turbinia

# Install yara rules and fraken binary.
RUN cd /opt \
    && git clone https://github.com/Neo23x0/signature-base.git \
    && sudo chown -R turbinia:turbinia /opt/signature-base \
    && find /opt/signature-base -type f -not -iname '*.yar' -not -iname '*.yara' -not -iname 'file-type-signatures.txt' -delete
COPY turbinia/config/rules/*.yar /opt/signature-base/yara/
# Install fraken binary from multi-stage build
RUN mkdir -p /opt/fraken
COPY --chown=turbinia:turbinia --from=fraken-builder /opt/fraken/fraken /opt/fraken/fraken

# Install container-explorer
RUN wget -O /tmp/container-explorer-setup.sh https://raw.githubusercontent.com/google/container-explorer/main/script/setup.sh
RUN chmod +x /tmp/container-explorer-setup.sh
RUN sudo /tmp/container-explorer-setup.sh install

# Setup turbinia user folders and permissions
RUN mkdir /etc/turbinia && mkdir -p /mnt/turbinia/ && mkdir -p /var/lib/turbinia/ \
    && mkdir -p /etc/turbinia/ && chown -R turbinia:turbinia /etc/turbinia/ \
    && mkdir -p /var/log/turbinia/ && chown -R turbinia:turbinia /mnt/turbinia/ \
    && chown -R turbinia:turbinia /var/lib/turbinia/ \
    && chown -R turbinia:turbinia /var/log/turbinia/ \
    && mkdir -p /home/turbinia && chown -R turbinia:turbinia /home/turbinia

# Install latest hashcat
RUN cd /home/turbinia \
    && wget https://hashcat.net/files/hashcat-6.2.6.7z \
    && 7z x hashcat-6.2.6.7z \
    && chown -R turbinia:turbinia /home/turbinia/hashcat-6.2.6/ \
    && cp /home/turbinia/hashcat-6.2.6/hashcat.bin /home/turbinia/hashcat-6.2.6/hashcat
ENV PATH="$PATH:/home/turbinia/hashcat-6.2.6/"

# Get a decent password list for john/hashcat
RUN cd /home/turbinia && echo "" > password.lst
RUN cd /home/turbinia && curl -s https://raw.githubusercontent.com/danielmiessler/SecLists/285474cf9bff85f3323c5a1ae436f78acd1cb62c/Passwords/UserPassCombo-Jay.txt >> password.lst
RUN cd /home/turbinia && curl -s https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt >> password.lst
RUN cp /home/turbinia/password.lst /root/
RUN echo ':\nd' > /home/turbinia/turbinia-password-cracking.rules

# Copy Kubernetes support tool to home folder
COPY --chown=turbinia:turbinia k8s/tools/check-lockfile.py /home/turbinia/check-lockfile.py

# Install Turbinia
# unshallow and fetch all tags so our build systems pickup the correct git tag if it's a shallow clone
# install turbinia and cleanup /tmp
ADD . /tmp/
RUN if $(cd /tmp/ && git rev-parse --is-shallow-repository); then cd /tmp/ && git fetch --prune --unshallow && git fetch --depth=1 origin +refs/tags/*:refs/tags/*; fi \
    && cd /tmp/ && python3 setup.py install

COPY docker/worker/start.sh /home/turbinia/start.sh
RUN chmod +rwx /home/turbinia/start.sh
USER turbinia
CMD ["/home/turbinia/start.sh"]
# Expose Prometheus endpoint.
EXPOSE 9200/tcp
