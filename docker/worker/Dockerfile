# Multi-stage build
# Use: docker build --no-cache --build-arg PPA_TRACK="[staging|stable] GOVERSION=[1.20.6|1.18|?]"

# Build 0 - fraken
FROM ubuntu:22.04 AS fraken-builder
RUN apt-get update && apt-get -y upgrade && apt-get -y install \
    automake \
    curl \
    dh-autoreconf \
    gcc \
    libjemalloc-dev \
    libprotobuf-c-dev \
    libssl-dev \
    libtool \
    make \
    pkg-config \
    sudo 
 #   musl-dev \
 #   musl-tools
# Add a symlink as we install the non-default golang 1.20 compiler (latest for 22.04)
#RUN ln -s /usr/lib/go-1.20/bin/go /usr/bin/go

# Install latest golang as ubuntu base image provides outdated version.
ARG GOVERSION=1.20.6
RUN curl -LO https://go.dev/dl/go$GOVERSION.linux-amd64.tar.gz
RUN tar -C /usr/local -xvf go$GOVERSION.linux-amd64.tar.gz
ENV PATH="$PATH:/usr/local/go/bin"

RUN mkdir -p /opt/fraken/yara
RUN cd /opt/fraken/yara && curl -s -L --retry 5 "$(curl -s -L --retry 5 https://api.github.com/repos/VirusTotal/Yara/releases/latest | sed -n 's/.*"tarball_url": "\(.*\)",.*/\1/p')"  | tar -xz --strip-components=1 
RUN cd /opt/fraken/yara && ./bootstrap.sh && ./configure && make && sudo make install && sudo ldconfig 
COPY tools/fraken/* /opt/fraken/
# TODO(rbdebere): Rework to use musl-gcc for full static build! 
#RUN cd /opt/fraken && CGO_ENABLED=1 CC=musl-gcc go build --ldflags="-linkmode=external -extldflags=-static" -tags yara_static -o fraken 
RUN cd /opt/fraken && go build -ldflags="-linkmode=external -extldflags=-static" -tags yara_static -o fraken 

# Build 1 - Turbinia Worker
FROM ubuntu:22.04 AS worker-builder
ENV DEBIAN_FRONTEND=noninteractive

ARG PPA_TRACK=stable

ENV PIP_NO_CACHE_DIR=1
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get -y upgrade && apt-get -y install \
    apt-transport-https \
    apt-utils \
    ca-certificates \
    curl \
    git \
    john \
    john-data \
    hashcat \
    hashcat-data \
    libleveldb1d \
    libleveldb-dev \
    libterm-readline-gnu-perl \
    lvm2 \
    python3-pip \
    software-properties-common \
    sudo \
    testdisk \
    wget \
    && apt-get clean && rm -rf /var/cache/apt/* /var/lib/apt/lists/*


ADD requirements.txt /tmp/
RUN cd /tmp/ && pip3 install --no-cache-dir -r requirements.txt

RUN pip3 install --no-cache-dir pip --upgrade
RUN pip3 install --no-cache-dir requests --upgrade
RUN pip3 install --no-cache-dir urllib3 cryptography --upgrade

# Install third-party worker dependencies
RUN pip3 install --no-cache-dir dfDewey
# TODO(hacktobeer) uncomment when protobuf lib dependency if fixed upstream
# RUN pip3 install pyhindsight

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
    --option Acquire::ForceIPv4=true --option Acquire::Retries=100 --option Acquire::http::Timeout=60 \
     && apt-get clean && rm -rf /var/cache/apt/* /var/lib/apt/lists/*

RUN useradd -r -s /bin/nologin -G disk,sudo -u 999 turbinia
RUN echo "turbinia ALL = (root) NOPASSWD: ALL" > /etc/sudoers.d/turbinia

RUN pip3 install --no-cache-dir impacket --no-deps

RUN cd /opt \
    && git clone https://github.com/Neo23x0/signature-base.git \
    && sudo chown -R turbinia:turbinia /opt/signature-base \
    && find /opt/signature-base/ -type f ! -iname "*.yar*" -delete

COPY turbinia/config/rules/*.yar /opt/signature-base/yara/

# copy fraken in
RUN mkdir -p /opt/fraken
COPY --chown=turbinia:turbinia --from=fraken-builder /opt/fraken/fraken /opt/fraken/fraken

RUN mkdir /etc/turbinia && mkdir -p /mnt/turbinia/ && mkdir -p /var/lib/turbinia/ \
    && mkdir -p /etc/turbinia/ && chown -R turbinia:turbinia /etc/turbinia/ \
    && mkdir -p /var/log/turbinia/ && chown -R turbinia:turbinia /mnt/turbinia/ \
    && chown -R turbinia:turbinia /var/lib/turbinia/ \
    && chown -R turbinia:turbinia /var/log/turbinia/ \
    && mkdir -p /home/turbinia && chown -R turbinia:turbinia /home/turbinia

# Get a decent password list
RUN cd /home/turbinia && echo "" > password.lst
RUN cd /home/turbinia && curl -s https://raw.githubusercontent.com/danielmiessler/SecLists/285474cf9bff85f3323c5a1ae436f78acd1cb62c/Passwords/UserPassCombo-Jay.txt >> password.lst
RUN cd /home/turbinia && curl -s https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt >> password.lst
RUN cp /home/turbinia/password.lst /root/

# Copy Kubernetes support tool to home folder
COPY --chown=turbinia:turbinia k8s/tools/check-lockfile.py /home/turbinia/check-lockfile.py

# Install container-explorer
RUN wget -O /tmp/container-explorer-setup.sh https://raw.githubusercontent.com/google/container-explorer/main/script/setup.sh
RUN chmod +x /tmp/container-explorer-setup.sh
RUN sudo /tmp/container-explorer-setup.sh install

ADD . /tmp/
# unshallow and fetch all tags so our build systems pickup the correct git tag if it's a shallow clone
# install turbinia and cleanup /tmp
RUN if $(cd /tmp/ && git rev-parse --is-shallow-repository); then cd /tmp/ && git fetch --prune --unshallow && git fetch --depth=1 origin +refs/tags/*:refs/tags/*; fi \
    && cd /tmp/ && python3 setup.py install \
    && find /tmp/ -mindepth 1 -delete

COPY docker/worker/start.sh /home/turbinia/start.sh
RUN chmod +rwx /home/turbinia/start.sh
USER turbinia
CMD ["/home/turbinia/start.sh"]
# Expose Prometheus endpoint.
EXPOSE 9200/tcp
