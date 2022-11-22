# Build stage for the web ui
FROM node:lts-alpine as build-stage
WORKDIR /tmp/web
COPY web/package*.json ./
RUN npm install
COPY web/. .
RUN npm run build

# Build Turbinia API Server, copy from build, and setup rest of requirements
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive 
COPY --from=build-stage /tmp/web/dist /web/dist
RUN apt-get update && apt-get -y install python3-pip git wget supervisor curl

RUN pip3 install pip --upgrade
RUN pip3 install urllib3 cryptography requests --upgrade

ADD requirements.txt /tmp/
RUN cd /tmp/ && pip3 install -r requirements.txt

ADD . /tmp/

# unshallow and fetch all tags so our build systems pickup the correct git tag if it's a shallow clone
RUN if $(cd /tmp/ && git rev-parse --is-shallow-repository); then cd /tmp/ && git fetch --prune --unshallow && git fetch --depth=1 origin +refs/tags/*:refs/tags/*; fi

RUN cd /tmp/ && python3 setup.py install

RUN useradd -r -s /bin/nologin -u 999 turbinia

RUN mkdir /etc/turbinia && mkdir -p /mnt/turbinia/ && mkdir -p /var/lib/turbinia/ \
    && mkdir -p /var/log/turbinia/ && chown -R turbinia:turbinia /mnt/turbinia/ \
    && mkdir -p /etc/turbinia/ \
    && chown -R turbinia:turbinia /var/lib/turbinia/ \
    && chown -R turbinia:turbinia /etc/turbinia/ \
    && chown -R turbinia:turbinia /var/log/turbinia/

COPY docker/api_server/start.sh /home/turbinia/start.sh
RUN chmod +rwx /home/turbinia/start.sh
USER turbinia
CMD ["/home/turbinia/start.sh"]
# Expose Prometheus and API endpoints.
EXPOSE 9200/tcp
EXPOSE 8000/tcp
