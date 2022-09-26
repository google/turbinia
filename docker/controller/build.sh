#!/bin/bash
docker build -t turbinia-controller:$1 .
docker tag turbinia-controller:$1 us-docker.pkg.dev/osdfir-registry/turbinia/release/turbinia-controller:$1