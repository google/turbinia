#!/bin/bash
echo "Pull docker images to local cache"
docker pull ubuntu:18.04
docker pull us-docker.pkg.dev/osdfir-registry/turbinia/release/turbinia-server-dev:latest
docker pull us-docker.pkg.dev/osdfir-registry/turbinia/release/turbinia-worker-dev:latest

echo "Build Turbinia server and worker Docker images"
docker build --cache-from=ubuntu:18.04,us-docker.pkg.dev/osdfir-registry/turbinia/release/turbinia-server-dev:latest -t turbinia-server-dev -f docker/server/Dockerfile .    
docker build --cache-from=ubuntu:18.04,us-docker.pkg.dev/osdfir-registry/turbinia/release/turbinia-worker-dev:latest -t turbinia-worker-dev -f docker/worker/Dockerfile .

echo "Patch docker-compose config to use locally build images"
sed -i -e 's/#image: "t/image: "t/g' -e 's/image: "u/#image: "u/g' ./docker/local/docker-compose.yml

echo "Startup local turbinia docker-compose stack"
run: docker-compose -f ./docker/local/docker-compose.yml up -d

echo "Sleep for 5 seconds to let the local stack boot up"
sleep 5s

echo "Show Docker containers and initial logs"
docker ps -a
docker logs turbinia-server
docker logs turbinia-worker

echo "Preparing directory layout for tests"
mkdir ./conf
mkdir ./evidence
chmod 777 ./evidence

echo "Creating Turbinia configuration"
sed -f ./docker/local/local-config.sed ./turbinia/config/turbinia_config_tmpl.py > ./conf/turbinia.conf

echo "Fetching evidence to process"
curl https://raw.githubusercontent.com/obsidianforensics/hindsight/master/tests/fixtures/profiles/60/History > History
tar -vzcf ./evidence/history.tgz History

echo "Display Turbinia configuration and evidence folder"
cat ./conf/turbinia.conf
ls -al ./evidence

echo "Creating Turbinia request"
docker exec -t turbinia-server turbiniactl -r 123456789 compresseddirectory -l /evidence/history.tgz 

echo "Sleeping for 60 seconds to let Turbinia process evidence"
sleep 60s

echo "Display Turbinia request status"
docker exec turbinia-server turbiniactl -a status -r $REQUEST_ID

echo "Show Turbinia server logs"
docker logs turbinia-server

echo "Show Turbinia worker logs"
docker logs turbinia-worker
 