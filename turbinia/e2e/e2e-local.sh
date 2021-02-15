#!/bin/bash
# This scripts executes a Turbinia end-to-end test aginst a running Turbinia stack.
# The evidence processed is Chrome Browser History.

echo "Create evidence folder"
mkdir ./evidence
chmod 777 ./evidence

echo "Download Chrome browser history artifact"
curl https://raw.githubusercontent.com/obsidianforensics/hindsight/master/tests/fixtures/profiles/60/History > History
tar -vzcf ./evidence/history.tgz History
ls -al ./evidence

echo "Create  Turbinia request"
docker exec -t turbinia-server turbiniactl -r 123456789 compresseddirectory -l /evidence/history.tgz 

echo "Sleep for 60 seconds to let Turbinia process evidence"
sleep 60s

echo "Display Turbinia request status"
docker exec turbinia-server turbiniactl -a status -r $REQUEST_ID


