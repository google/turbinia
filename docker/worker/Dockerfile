FROM ubuntu:22.04

# Use: docker build --no-cache --build-arg PPA_TRACK="[staging|stable]"
ARG PPA_TRACK=stable

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get -y install \
    apt-transport-https \
    apt-utils \
    automake \
    ca-certificates \
    curl \
    dh-autoreconf \
    gcc \
    git \
    golang \
    go-bindata \
    john \
    john-data \
    hashcat \
    hashcat-data \
    libjemalloc-dev \
    libleveldb1d \
    libleveldb-dev \
    libprotobuf-c-dev \
    libssl-dev \
    libterm-readline-gnu-perl \
    libtool \
    lvm2 \
    make \
    pkg-config \
    python3-pip \
    software-properties-common \
    sudo \
    testdisk \
    wget \
    && rm -rf /var/lib/apt/lists/*

ADD requirements.txt /tmp/
RUN cd /tmp/ && pip3 install -r requirements.txt

RUN pip3 install pip --upgrade
RUN pip3 install requests --upgrade
RUN pip3 install urllib3 cryptography --upgrade

# Install third-party worker dependencies
RUN pip3 install dfDewey
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
RUN apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys 0x5e80511b10c598b8 \
    && add-apt-repository -y ppa:gift/$PPA_TRACK
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
    --option Acquire::ForceIPv4=true --option Acquire::Retries=100 --option Acquire::http::Timeout=60

RUN useradd -r -s /bin/nologin -G disk,sudo -u 999 turbinia
RUN echo "turbinia ALL = (root) NOPASSWD: ALL" > /etc/sudoers.d/turbinia

RUN pip3 install impacket --no-deps

RUN cd /opt \
    && git clone https://github.com/Neo23x0/signature-base.git \
    && sudo chown -R turbinia:turbinia /opt/signature-base

COPY turbinia/config/rules/*.yar /opt/signature-base/yara/

RUN mkdir -p /opt/fraken/yara && chown -R turbinia:turbinia /opt/fraken
COPY --chown=turbinia:turbinia tools/fraken/* /opt/fraken/
RUN cd /opt/fraken/yara && curl -s -L --retry 5 "$(curl -s -L --retry 5 https://api.github.com/repos/VirusTotal/Yara/releases/latest | sed -n 's/.*"tarball_url": "\(.*\)",.*/\1/p')"  | tar -xz --strip-components=1
RUN cd /opt/fraken/yara && ./bootstrap.sh \
    && ./configure \
    && make && sudo make install && sudo ldconfig
RUN cd /opt/fraken && go build -ldflags="-linkmode=external -extldflags=-ljemalloc" -o fraken

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
COPY k8s/tools/check-lockfile.py /home/turbinia/check-lockfile.py
RUN chown turbinia:turbinia /home/turbinia/check-lockfile.py

# Install container-explorer
RUN wget -O /tmp/container-explorer-setup.sh https://raw.githubusercontent.com/google/container-explorer/main/script/setup.sh
RUN chmod +x /tmp/container-explorer-setup.sh
RUN sudo /tmp/container-explorer-setup.sh install

ADD . /tmp/
# unshallow and fetch all tags so our build systems pickup the correct git tag if it's a shallow clone
RUN if $(cd /tmp/ && git rev-parse --is-shallow-repository); then cd /tmp/ && git fetch --prune --unshallow && git fetch --depth=1 origin +refs/tags/*:refs/tags/*; fi
RUN cd /tmp/ && python3 setup.py install

COPY docker/worker/start.sh /home/turbinia/start.sh
RUN chmod +rwx /home/turbinia/start.sh
USER turbinia
CMD ["/home/turbinia/start.sh"]
# Expose Prometheus endpoint.
EXPOSE 9200/tcp
