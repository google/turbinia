FROM ubuntu:20.04

ENV DEBIAN_FRONTEND=noninteractive 
RUN apt-get update && apt-get -y install \
    apt-transport-https \
    apt-utils \
    ca-certificates \
    git \
    libterm-readline-gnu-perl \
    python3-pip \
    software-properties-common \
    lsof \
    vim \
    curl \
    sudo \
    && rm -rf /var/lib/apt/lists/*

RUN pip3 install pip --upgrade
RUN pip3 install urllib3 cryptography requests --upgrade

ADD requirements.txt /tmp/
RUN cd /tmp/ && pip3 install -r requirements.txt

ADD . /tmp/
# unshallow and fetch all tags so our build systems pickup the correct git tag if it's a shallow clone
RUN if $(cd /tmp/ && git rev-parse --is-shallow-repository); then cd /tmp/ && git fetch --prune --unshallow && git fetch --depth=1 origin +refs/tags/*:refs/tags/*; fi

RUN cd /tmp/ && python3 setup.py install

RUN useradd -r -s /bin/nologin -G disk,sudo -u 999 turbinia
RUN echo "turbinia ALL = (root) NOPASSWD: ALL" > /etc/sudoers.d/turbinia

RUN mkdir /etc/turbinia && mkdir -p /mnt/turbinia/ && mkdir -p /var/lib/turbinia/ \
    && mkdir -p /var/log/turbinia/ && chown -R turbinia:turbinia /mnt/turbinia/ \
    && mkdir -p /etc/turbinia/ \
    && chown -R turbinia:turbinia /var/lib/turbinia/ \
    && chown -R turbinia:turbinia /etc/turbinia/ \
    && chown -R turbinia:turbinia /var/log/turbinia/

COPY docker/controller/start.sh /home/turbinia/start.sh
COPY k8s/tools/load-test.sh /home/turbinia/load-test.sh
RUN chmod +rwx /home/turbinia/start.sh /home/turbinia/load-test.sh && chown -R turbinia:turbinia /home/turbinia/
USER turbinia
CMD ["/home/turbinia/start.sh"]