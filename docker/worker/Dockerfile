FROM ubuntu:20.04

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get -y install \
    apt-transport-https \
    apt-utils \
    ca-certificates \
    git \
    libleveldb1d \
    libleveldb-dev \
    libterm-readline-gnu-perl \
    python3-pip \
    python3.8-venv \
    software-properties-common \
    sudo \
    testdisk

RUN apt-get -y install build-essential git \
    libssl-dev zlib1g-dev yasm libgmp-dev libpcap-dev \
    pkg-config libbz2-dev ocl-icd-opencl-dev \
    opencl-headers pocl-opencl-icd

RUN rm -rf /var/lib/apt/lists/*

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

# Get new version of John from Git
RUN cd /opt/ && git clone https://github.com/openwall/john
RUN chown -R turbinia:turbinia /opt/john/
RUN cd /opt/john/src && ./configure && make -s clean && make -sj4

ENV PATH="/opt/john/run:$PATH"

# Get install Impacket from Git in a venv
RUN python3 -m venv /opt/impacket-env
RUN chown -R turbinia:turbinia /opt/impacket-env
RUN chmod +x /opt/impacket-env/bin/activate
RUN mkdir -p /home/turbinia/impacket && chown turbinia:turbinia /home/turbinia/impacket
RUN cd /home/turbinia/impacket && git clone https://github.com/SecureAuthCorp/impacket.git
RUN . /opt/impacket-env/bin/activate && pip install wheel && cd /home/turbinia/impacket/impacket && python3 -m pip install .
RUN cp /home/turbinia/impacket/impacket/examples/secretsdump.py /usr/bin/

RUN mkdir /etc/turbinia && mkdir -p /mnt/turbinia/ && mkdir -p /var/lib/turbinia/ \
    && mkdir -p /etc/turbinia/ && chown -R turbinia:turbinia /etc/turbinia/ \
    && mkdir -p /var/log/turbinia/ && chown -R turbinia:turbinia /mnt/turbinia/ \
    && chown -R turbinia:turbinia /var/lib/turbinia/ \
    && chown -R turbinia:turbinia /var/log/turbinia/ \
    && mkdir -p /home/turbinia/.john && chown -R turbinia:turbinia /home/turbinia/

COPY docker/worker/start.sh /home/turbinia/start.sh
RUN chmod +x /home/turbinia/start.sh
USER turbinia
CMD ["/home/turbinia/start.sh"]
# Expose Prometheus endpoint.
EXPOSE 8000/tcp
