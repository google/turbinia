FROM ubuntu:20.04

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get -y install \
    apt-transport-https \
    apt-utils \
    ca-certificates \
    git \
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
    && rm -rf /var/lib/apt/lists/*

ADD requirements.txt /tmp/
RUN cd /tmp/ && pip3 install -r requirements.txt

RUN pip3 install pip --upgrade
RUN pip3 install requests --upgrade
RUN pip3 install urllib3 cryptography --upgrade

# Install third-party worker dependencies
RUN pip3 install pyhindsight

# Install Plaso, bulkextractor and docker-explorer
RUN apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys 0x5e80511b10c598b8 \
    && add-apt-repository -y ppa:gift/stable
RUN apt-get -y install \
    bulk-extractor \
    docker-explorer-tools \
    libbde-tools \
    libewf \
    libewf-python3 \
    plaso-tools \
    python3-dfvfs \
    python3-plaso \
    sleuthkit \
    --option Acquire::ForceIPv4=true --option Acquire::Retries=100 --option Acquire::http::Timeout=60

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
    && chown -R turbinia:turbinia /var/log/turbinia/ \
    && mkdir -p /home/turbinia && chown -R turbinia:turbinia /home/turbinia

# Get a decent password list
RUN cd /home/turbinia && wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt -O password.lst
RUN cp /home/turbinia/password.lst /root/

RUN pip3 install impacket --no-deps

COPY docker/worker/start.sh /home/turbinia/start.sh
RUN chmod +rwx /home/turbinia/start.sh
USER turbinia
CMD ["/home/turbinia/start.sh"]
# Expose Prometheus endpoint.
EXPOSE 8000/tcp
