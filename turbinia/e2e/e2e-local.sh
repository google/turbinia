#!/bin/bash
# This scripts executes a Turbinia end-to-end test against a local 
# docker-compose Turbinia stack
# The evidence processed is Chrome Browser History.

echo "Create evidence folder"
mkdir ./input
chmod 777 ./input

echo "Download Chrome browser history artifact"
curl https://raw.githubusercontent.com/obsidianforensics/hindsight/master/tests/fixtures/profiles/60/History > History
tar -vzcf ./input/history.tgz History
ls -al ./input/

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
docker exec -t turbinia-server turbiniactl -r 123456789 compresseddirectory -l /input/history.tgz 

echo "Sleep for 60 seconds to let Turbinia process evidence"
sleep 60s

echo "Display Turbinia request status"
docker exec turbinia-server turbiniactl -a status -r $REQUEST_ID
