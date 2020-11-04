#!/bin/bash
docker build -t prometheus-server:$1 .
docker tag prometheus-server:$1  gcr.io/oss-forensics-registry/turbinia/prometheus-server:$1
