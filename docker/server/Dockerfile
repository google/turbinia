# Can also pass this in as something like
# https://github.com/google/timesketch/archive/master.zip in order to install
# from different branches or TAGs.
ARG turbinia_version=turbinia

FROM ubuntu:18.04

RUN apt-get update && apt-get -y install \
apt-transport-https \
apt-utils \
ca-certificates \
libterm-readline-gnu-perl \
python3 \
python3-pip \
software-properties-common \
&& rm -rf /var/lib/apt/lists/*

RUN pip3 install pip --upgrade
RUN pip3 install urllib3 cryptography --upgrade

RUN pip3 install $turbinia_version

RUN useradd -r -s /bin/nologin -G disk turbinia

RUN mkdir /etc/turbinia && mkdir -p /mnt/turbinia/ && mkdir -p /var/lib/turbinia/ \
&& mkdir -p /var/log/turbinia/ && chown -R turbinia:turbinia /mnt/turbinia/ \
&& mkdir -p /etc/turbinia/ \
&& chown -R turbinia:turbinia /var/lib/turbinia/ \
&& chown -R turbinia:turbinia /etc/turbinia/ \
&& chown -R turbinia:turbinia /var/log/turbinia/

COPY docker/server/start.sh /home/turbinia/start.sh
RUN chmod +x /home/turbinia/start.sh
USER turbinia
CMD ["/home/turbinia/start.sh"]
