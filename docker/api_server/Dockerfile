# Build stage for the web ui
FROM node:lts-alpine as build-stage
WORKDIR /tmp/web
COPY web/package*.json ./
RUN npm install
COPY web/. .
RUN npm run build

# Build Turbinia API Server, copy from build, and setup rest of requirements
FROM --platform=linux/amd64 ubuntu:24.04 as build-stage2

ENV DEBIAN_FRONTEND=noninteractive \
    PIP_NO_CACHE_DIR=1 

COPY --from=build-stage /tmp/web/dist /web/dist
RUN apt-get update && apt-get -y upgrade
RUN apt-get -y install git python3-pip python3.12-venv

RUN useradd -r -s /sbin/nologin -u 999 turbinia
RUN mkdir /etc/turbinia && mkdir -p /mnt/turbinia/ && mkdir -p /var/lib/turbinia/ \
    && mkdir -p /var/log/turbinia/ && chown -R turbinia:turbinia /mnt/turbinia/ \
    && mkdir -p /etc/turbinia/ \
    && chown -R turbinia:turbinia /var/lib/turbinia/ \
    && chown -R turbinia:turbinia /etc/turbinia/ \
    && chown -R turbinia:turbinia /var/log/turbinia/ \
    && mkdir -p /home/turbinia && chown -R turbinia:turbinia /home/turbinia

# Drop privileges and set the working directory
USER turbinia
WORKDIR /home/turbinia

# Install poetry
RUN python3 -m venv .venv
ENV PATH="/home/turbinia/.local/bin:/home/turbinia/.venv/bin:$PATH" \
    VIRTUAL_ENV=/home/turbinia/.venv
RUN python3 -m pip install poetry

# Copy requirements and install dependencies to cache them in docker layer
COPY --chown=turbinia:turbinia ./pyproject.toml ./poetry.toml ./poetry.lock /home/turbinia/
RUN poetry install --no-interaction --no-ansi --no-root

# Copy the source directory to the container
COPY --chown=turbinia:turbinia . /home/turbinia/
COPY --chown=turbinia:turbinia docker/api_server/start.sh /home/turbinia/start.sh
RUN chmod +rwx /home/turbinia/start.sh

# Install Turbinia package -- will skip dependencies if installed
RUN poetry install --no-interaction --no-ansi

# Create debug and env variables
ARG TURBINIA_DEBUG
ARG TURBINIA_DEBUG_PORT
ENV TURBINIA_DEBUG ${TURBINIA_DEBUG:-0}
ENV TURBINIA_DEBUG_PORT ${TURBINIA_DEBUG_PORT:-30000}

CMD ["/home/turbinia/start.sh"]
# Expose Prometheus and API endpoints.
EXPOSE 9200/tcp
EXPOSE 8000/tcp
