#!/bin/bash
# This scripts executes a Turbinia end-to-end test against a local 
# docker-compose Turbinia stack
# The evidence processed is Chrome Browser History.

echo "Create evidence folder"
mkdir -p ./evidence
sudo chmod 777 ./evidence

echo "Download Chrome browser history artifact"
curl https://raw.githubusercontent.com/obsidianforensics/hindsight/master/tests/fixtures/profiles/60/History > History
tar -vzcf ./evidence/history.tgz History
ls -al ./evidence/

echo "Startup local turbinia docker-compose stack"
docker-compose -f ./docker/local/docker-compose.yml up -d

echo "Sleep for 5s"
sleep 5s

echo "Show running instances"
docker ps -a

echo "Show container logs"
docker logs turbinia-server
docker logs turbinia-worker

echo "Create  Turbinia request"
docker exec -t turbinia-server turbiniactl -r 123456789 compresseddirectory -l /evidence/history.tgz 

echo "Display Turbinia request status"
docker exec turbinia-server turbiniactl -w -a status -r 123456789
