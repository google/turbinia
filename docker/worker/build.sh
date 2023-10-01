#!/bin/bash
docker build -t turbinia-worker:$1 --target turbinia-worker .
docker tag turbinia-worker:$1 us-docker.pkg.dev/osdfir-registry/turbinia/release/turbinia-worker:$1
