#!/bin/bash
docker build -t turbinia-server:$1 .
docker tag turbinia-server:$1 us-docker.pkg.dev/osdfir-registry/turbinia/release/turbinia-server:$1
