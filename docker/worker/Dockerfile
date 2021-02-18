FROM ubuntu:20.04

ENV DEBIAN_FRONTEND=noninteractive 
RUN apt-get update && apt-get -y install \
    apt-transport-https \
    apt-utils \
    ca-certificates \
    git \
    john \
    john-data \
    libleveldb1d \
    libleveldb-dev \
    libterm-readline-gnu-perl \
    python3-pip \
    software-properties-common \
    sudo \
    testdisk \
    sleuthkit

ADD requirements.txt /tmp/
RUN cd /tmp/ && pip3 install -r requirements.txt

RUN pip3 install pip --upgrade
RUN pip3 install urllib3 cryptography requests --upgrade

# Install third-party worker dependencies
RUN pip3 install pyhindsight

# Install Plaso and docker-explorer
RUN add-apt-repository -y ppa:gift/stable
RUN apt-key list
RUN apt-get -y install \
    docker-explorer-tools \
    libewf \
    libewf-python3 \
    plaso-tools \
    python3-dfvfs \
    python3-plaso \
    --option Acquire::ForceIPv4=true --option Acquire::Retries=100 --option Acquire::http::Timeout=60

# Install BulkExtractor
RUN apt-get -y install bulk-extractor \
    && rm -rf /var/lib/apt/lists/*

ADD . /tmp/
# unshallow and fetch all tags so our build systems pickup the correct git tag if it's a shallow clone
RUN if $(cd /tmp/ && git rev-parse --is-shallow-repository); then cd /tmp/ && git fetch --prune --unshallow && git fetch --depth=1 origin +refs/tags/*:refs/tags/*; fi
RUN cd /tmp/ && python3 setup.py install

RUN useradd -r -s /bin/nologin -G disk,sudo turbinia
RUN echo "turbinia ALL = (root) NOPASSWD: ALL" > /etc/sudoers.d/turbinia

RUN mkdir /etc/turbinia && mkdir -p /mnt/turbinia/ && mkdir -p /var/lib/turbinia/ \
    && mkdir -p /etc/turbinia/ && chown -R turbinia:turbinia /etc/turbinia/ \
    && mkdir -p /var/log/turbinia/ && chown -R turbinia:turbinia /mnt/turbinia/ \
    && chown -R turbinia:turbinia /var/lib/turbinia/ \
    && chown -R turbinia:turbinia /var/log/turbinia/

COPY docker/worker/start.sh /home/turbinia/start.sh
RUN chmod +x /home/turbinia/start.sh
USER turbinia
CMD ["/home/turbinia/start.sh"]
# Expose Prometheus endpoint.
EXPOSE 8000/tcp
