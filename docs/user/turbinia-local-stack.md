## Turbinia local stack using Docker
Turbinia can be run locally without any Cloud components using Docker. It will use Redis, Celery and local disk to store data and perform message broker functionality.

### Caveats
rawdisk: As Turbinia uses the loop device to mount different types of evidence (eg raw disks) the host operating system should support the loop device. Linux is currently the only OS that supports the processing of raw disks.

googleclouddisk: Turbinia as local stack cannot currently process Google Cloud disks.

### Running

#### Step 1
Checkout the [Turbinia source code](https://github.com/google/turbinia). If you intend to start developing please [fork](https://docs.github.com/en/github/getting-started-with-github/fork-a-repo) the repository on github first and check out your own forked instance.
```
$ git clone https://github.com/google/turbinia.git
$ cd turbinia
```
#### Step 2
Generate configuration file using sed with default local stack values to the ```./conf``` folder. This folder will be mapped by docker compose into the containers.
```
$ mkdir ./conf
$ sed -f docker/local/local-config.sed turbinia/config/turbinia_config_tmpl.py > conf/turbinia.conf
```
#### Step 3
Let's bring up the local Turbinia stack
```
$ docker-compose -f ./docker/local/docker-compose.yml up
```
Redis, a Turbinia server and worker should now be running on your local system and a local persistent 'evidence' folder will have been created containing the Turbinia log file and processing output.
Note: Redis will store it's data in a volume that is mapped to ```./redis-data/```. You can adjust this in the docker-compose.yml configuration.
#### Step 4
Let's process evidence to test your setup, eg a Chrome Browser history file.
```
$ curl https://raw.githubusercontent.com/obsidianforensics/hindsight/master/tests/fixtures/profiles/60/History > History
$ tar -vzcf ./evidence/history.tgz History
```
This command runs the turbinia client, turbiniactl, within the turbinia server docker container and generates a processing request.
```
$ docker exec -ti turbinia-server turbiniactl compresseddirectory -l /evidence/history.tgz
```
This will create a task in Turbinia to process the evidence file. A request ID will be returned and we can query the status with below command.
```
$ docker exec -ti turbinia-server turbiniactl -a status -r {REQUEST_ID}
```
There will be server and worker output displayed both on the docker-compose terminal as well as in the ```./evidence``` folder.
