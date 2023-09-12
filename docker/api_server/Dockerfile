# Build stage for the web ui
FROM node:lts-alpine as build-stage
WORKDIR /tmp/web
COPY web/package*.json ./
RUN npm install
COPY web/. .
RUN npm run build

# Build Turbinia API Server, copy from build, and setup rest of requirements
FROM ubuntu:22.04 as build-stage2

ENV DEBIAN_FRONTEND=noninteractive 
COPY --from=build-stage /tmp/web/dist /web/dist
RUN apt-get update && apt-get -y upgrade
RUN apt-get -y install git python3-pip
RUN pip3 install pip --upgrade

# Use the REELASE_TAG argument passed via --build-arg cli argument
ARG RELEASE_TAG
RUN pip3 install turbinia==$RELEASE_TAG

RUN useradd -r -s /bin/nologinpoet -u 999 turbinia
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
