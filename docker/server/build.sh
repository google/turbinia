#!/bin/bash
docker build -t turbinia-server:$1 .
docker tag turbinia-server:$1 gcr.io/ramses-test3/turbinia-server:$1