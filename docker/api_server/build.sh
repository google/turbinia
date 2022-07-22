#!/bin/bash
docker build -t turbinia-api-server-dev:$1 .
docker tag turbinia-api-server-dev:$1  gcr.io/oss-forensics-registry/turbinia/turbinia-api-server-dev:$1
