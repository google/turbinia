FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive 
RUN apt-get update && apt-get -y upgrade
RUN apt-get -y install \
    apt-transport-https \
    apt-utils \
    ca-certificates \
    libterm-readline-gnu-perl \
    software-properties-common \
    curl \ 
    wget \
    && rm -rf /var/lib/apt/lists/*
RUN useradd -r -s /bin/nologin -u 999 turbinia
RUN mkdir -p /etc/turbinia && chown -R turbinia:turbinia /etc/turbinia/


COPY docker/oauth2_proxy/start.sh /home/turbinia/start.sh
RUN chmod +rwx /home/turbinia/start.sh

# Copy oauth2 proxy and start it
RUN mkdir /oauth2-proxy
RUN cd /oauth2-proxy && curl https://api.github.com/repos/oauth2-proxy/oauth2-proxy/releases/latest | grep -E 'browser_download_url.*linux-amd64.tar.gz' | cut -d'"' -f4 | head -1 | xargs -n1 wget -q -O proxy.tar.gz && tar xzf proxy.tar.gz
RUN cp /oauth2-proxy/oauth2-proxy*.linux-amd64/oauth2-proxy /usr/local/bin/oauth2-proxy
RUN chmod +x /usr/local/bin/oauth2-proxy

USER turbinia
CMD ["/home/turbinia/start.sh"]
# Expose Prometheus and Oauth2 endpoints.
EXPOSE 9200/tcp
EXPOSE 8080/tcp
