#!/bin/bash
docker build -t turbinia-api-server:$1 .
docker tag turbinia-api-server:$1 us-docker.pkg.dev/osdfir-registry/turbinia/release/turbinia-api-server:$1
