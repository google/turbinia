FROM ubuntu:20.04

ENV DEBIAN_FRONTEND=noninteractive 
RUN apt-get update && apt-get -y install python3-pip git wget supervisor curl

RUN pip3 install pip --upgrade
RUN pip3 install requests --upgrade
RUN pip3 install urllib3 cryptography --upgrade

ADD requirements.txt /tmp/
RUN cd /tmp/ && pip3 install -r requirements.txt

ADD . /tmp/

# unshallow and fetch all tags so our build systems pickup the correct git tag if it's a shallow clone
RUN if $(cd /tmp/ && git rev-parse --is-shallow-repository); then cd /tmp/ && git fetch --prune --unshallow && git fetch --depth=1 origin +refs/tags/*:refs/tags/*; fi

RUN cd /tmp/ && python3 setup.py install

RUN useradd -r -s /bin/nologin -G disk turbinia

RUN mkdir /etc/turbinia && mkdir -p /mnt/turbinia/ && mkdir -p /var/lib/turbinia/ \
    && mkdir -p /var/log/turbinia/ && chown -R turbinia:turbinia /mnt/turbinia/ \
    && mkdir -p /etc/turbinia/ \
    && chown -R turbinia:turbinia /var/lib/turbinia/ \
    && chown -R turbinia:turbinia /etc/turbinia/ \
    && chown -R turbinia:turbinia /var/log/turbinia/

COPY docker/api_server/start.sh /home/turbinia/start.sh
RUN chmod +rwx /home/turbinia/start.sh

# Setup OAuth2-proxy
COPY docker/api_server/oauth2_web.cfg /etc/turbinia/oauth2_web.cfg
RUN chown turbinia:turbinia /etc/turbinia/oauth2_web.cfg

RUN mkdir /oauth2-proxy

RUN cd /oauth2-proxy && curl https://api.github.com/repos/oauth2-proxy/oauth2-proxy/releases/latest | grep -E 'browser_download_url.*linux-amd64.tar.gz' | cut -d'"' -f4 | xargs -n1 wget -q -O proxy.tar.gz && tar xzf proxy.tar.gz

RUN cp /oauth2-proxy/oauth2-proxy*.linux-amd64/oauth2-proxy /usr/local/bin/oauth2-proxy
RUN chmod +x /usr/local/bin/oauth2-proxy
RUN touch /etc/turbinia/auth.txt

COPY docker/api_server/turbinia_services.conf /etc/supervisor/conf.d/turbinia_services.conf

CMD ["/home/turbinia/start.sh"]

# Expose tcp ports
EXPOSE 8000/tcp
EXPOSE 8080/tcp
