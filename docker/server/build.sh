#!/bin/bash
docker build -t turbinia-server:$1 .
docker tag turbinia-server:$1  gcr.io/oss-forensics-registry/turbinia/turbinia-server:$1
