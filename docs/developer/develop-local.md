# Developing on a local Turbinia setup (no cloud required)

See [here](../user/turbinia-local-stack.md) on how to setup the local Turbinia stack with Docker.

After you have the local stack up and running a usual development cycle would look like below.

## Before you start
*   Check out the [How it Works](../user/how-it-works.md) page to see how the different
    components work within Turbinia.
*   Make sure to follow the Turbinia
    [developer contribution guide](contributing.md).

#### Step 1
Fork Turbinia on github and create a new feature branch to work on.
```
$ git clone https://github.com/[your-github-user-id]/turbinia.git
$ git checkout -b my-new-feature
$ cd turbinia
```
#### Step 2
Add some awesome new feature, maybe [develop a new task](./developing-new-tasks.md)?
#### Step 3
Rebuild Turbinia server and/or worker Docker images.
```
$ docker build -t turbinia-worker-dev -f docker/worker/Dockerfile .
```
#### Step 4
Change the ```image:``` location in the ```docker/local/docker-compose.yml``` file to point to your localy build image (eg turbinia-worker-dev).

#### Step 5
Let's bring up the local Turbinia stack 
```
$ docker-compose -f ./docker/local/docker-compose.yml up
```
#### Step 6
Let's process evidence to test your setup, in this case a Chrome Browser history file but you will likely want to use specific evidence to test your new functionality.
```
$ curl https://raw.githubusercontent.com/obsidianforensics/hindsight/master/tests/fixtures/profiles/60/History > History
$ tar -vzcf ./evidence/history.tgz History
$ docker exec -ti turbinia-server turbiniactl compresseddirectory -l /evidence/history.tgz
```
This will create a task in Turbinia to process the evidence file. A task ID will be returned and we can query the status with below command.
```
$ docker exec -ti turbinia-server turbiniactl -a status -r b998efb5dcb64949963d9c72ba143c1a
```
#### Step 7
Test and debug your new feature and repeat steps 1-7 until satisfied. 
