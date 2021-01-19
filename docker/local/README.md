## Turbinia local stack (running and developing)
Turbinia can be run locally without any Cloud components. It will use Redis, Celery and local disk to store data and perform message broker functionality.

### Caveats
rawdisk: As Turbinia uses the loop device to mount different types of evidence (eg raw disks) the host operating system should support the loop device. Linux is currently the only OS that supports the processing of raw disks. It is possible to process different evidence types, eg compresseddirectory, using the local stack on OSX or Windows.

googleclouddisk: Turbinia as local stack can currently not process Google Cloud disks.

### Running and development
Running the local stack is similar to the local development flow described below while skipping steps 2 and 3.

Development using the local stack is easy.

#### Step 1
Checkout Turbinia source code and create a new branch.
```
$ git clone https://github.com/google/turbinia.git
$ git checkout -b my-new-feature
$ cd turbinia
```
#### Step 2
Add your awesome new feature, super small bugfix or documentation update :)
#### Step 3
Change the ```image:``` location in the ```docker/local/docker-compose.yml``` file to point to your localy build image (eg turbinia-server-dev).
#### Step 4
Copy a configuration template for the local stack to the ```./conf`` folder (create the folder if it does not exist).
```
$ cp docker/local/turbinia-local-template.conf ./conf/turbinia.conf
```
#### Step 5
Now build a docker (server) image (this will take some serious time the first build!)
```
$ docker build -t turbinia-server-dev -f docker/server/Dockerfile .
```
#### Step 6
Let's bring up the local Turbinia stack
```
$ docker-compose -f ./docker/local/docker-compose.yml up
```
Redis, a Turbinia server and worker should now be running on your local system and a local persistent 'evidence' folder will have been created with the Turbinia log file and processing output.
#### Step 6
Let's send process evidence, eg some Chrome Browser history file.
```
$ curl https://github.com/obsidianforensics/hindsight/raw/master/tests/fixtures/profiles/60/History > History
$ tar -vzcf ./evidence/history.tgz History
$ docker exec -ti turbinia-server turbiniactl compresseddirectory -l /evidence/history.tgz
```
This will create a task in Turbinia to process the evidence file. A task ID will be returned and we can query the status with below command.
```
$ docker exec -ti turbinia-server turbiniactl -a status -r b998efb5dcb64949963d9c72ba143c1a
```
There will be server and worker output displayed both on the docker-compose terminal as well as in the ```./evidence`` folder log files.

Debug your code and repeat steps 4-6 to make your code perfect :).

