#!/bin/bash
docker build -t turbinia-worker:$1 .
docker tag turbinia-worker:$1 gcr.io/ramses-test3/turbinia-worker:$1
