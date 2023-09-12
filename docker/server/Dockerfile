FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive 
ENV PIP_NO_CACHE_DIR=1
RUN apt-get update && apt-get -y upgrade && apt-get -y install \
    apt-transport-https \
    apt-utils \
    ca-certificates \
    git \
    libterm-readline-gnu-perl \
    python3-pip \
    software-properties-common \
    sudo \
    && apt-get clean && rm -rf /var/cache/apt/* /var/lib/apt/lists/*

RUN pip3 install pip --upgrade
ADD . /tmp/

# Use the REELASE_TAG argument passed via --build-arg cli argument
ARG RELEASE_TAG
RUN pip3 install turbinia==$RELEASE_TAG

RUN useradd -r -s /bin/nologin -u 999 turbinia

RUN mkdir /etc/turbinia && mkdir -p /mnt/turbinia/ && mkdir -p /var/lib/turbinia/ \
    && mkdir -p /var/log/turbinia/ && chown -R turbinia:turbinia /mnt/turbinia/ \
    && mkdir -p /etc/turbinia/ \
    && chown -R turbinia:turbinia /var/lib/turbinia/ \
    && chown -R turbinia:turbinia /etc/turbinia/ \
    && chown -R turbinia:turbinia /var/log/turbinia/

COPY docker/server/start.sh /home/turbinia/start.sh
RUN chmod +rwx /home/turbinia/start.sh
USER turbinia
CMD ["/home/turbinia/start.sh"]
# Expose Prometheus endpoint.
EXPOSE 9200/tcp
