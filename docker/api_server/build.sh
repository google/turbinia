#!/bin/bash
docker build -t turbinia-api-server:$1 .
docker tag turbinia-api-server:$1  gcr.io/oss-forensics-registry/turbinia/turbinia-api-server:$1
