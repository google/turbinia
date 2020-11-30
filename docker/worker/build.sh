#!/bin/bash
docker build -t turbinia-worker:$1 .
docker tag turbinia-worker:$1 gcr.io/oss-forensics-registry/turbinia/turbinia-worker:$1
