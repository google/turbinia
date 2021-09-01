#!/bin/bash
# This scripts executes a Turbinia end-to-end test against a local 
# docker-compose Turbinia stack
# The evidence processed is a prepared raw disk image.

# Set default return value
RET=0

echo "Create evidence folder"
mkdir -p ./evidence
sudo chmod 777 ./evidence

echo "==> Copy test artifacts to /evidence"
cp ./test_data/artifact_disk.dd ./evidence/

echo "==> Startup local turbinia docker-compose stack"
export TURBINIA_EXTRA_ARGS="-d"
docker-compose -f ./docker/local/docker-compose.yml up -d

echo "==> Sleep for 5s"
sleep 5s

echo "==> Show running instances"
docker ps -a

echo "==> Show loop device availability in worker"
docker exec -t turbinia-worker /sbin/losetup -a
docker exec -t turbinia-worker ls -al /dev/loop*

echo "==> Show evidence volume contents in worker"
docker exec -t turbinia-worker ls -al /evidence/

echo "==> Show container logs"
docker logs turbinia-server
docker logs turbinia-worker

echo "==> Create  Turbinia request"
docker exec -t turbinia-server turbiniactl -r 123456789 rawdisk -l /evidence/artifact_disk.dd

echo "==> Sleep for 150 seconds to let Turbinia process evidence"
sleep 150s

echo "==> Display Turbinia request status"
docker exec turbinia-server turbiniactl -a status -r 123456789

echo "==> See if any tasks failed"
FAILED=`docker exec turbinia-server turbiniactl -a status -r 123456789 | awk '/Failed Tasks/,/\* None/' | wc -l`
if [ "$FAILED" != "2" ]; then
    echo 'Tasks failed!'
    RET=1
fi

echo "==> Show Turbinia server logs"
docker logs turbinia-server

echo "==> Show Turbinia worker logs"
docker logs turbinia-worker

echo "==> Show evidence volume contents in worker"
docker exec -t turbinia-worker ls -al /evidence/

exit $RET
