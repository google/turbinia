# Developing with Visual Studio Code (no cloud required)

## Introduction
This procedure will get you up and running with a Visual Studio Code environment for Turbinia development. The provided configuration files will create a development container containing all dependencies, pylint and yapf correctly setup and launch configurations for both client, server and workers. With this setup it is possible to initiate full Turbinia debug sessions including breakpoints, watches and stepping.

You can set Visual Studio Code up to run a local stack (using redis and celery) or use a hybrid GCP stack (using pubsub, datastore and cloud functions). We advice you to run a local stack if you don't need to debug or develop Turbinia GCP functionality.

## Before you start
*   Check out the [How it Works](../user/how-it-works.md) page to see how the different
    components work within Turbinia.
*   Make sure to follow the Turbinia
    [developer contribution guide](contributing.md).

#### Step 1 - Install required software
Prepare your OS:
* Install Visual Studio Code and install the Remote Development extension pack.
* Install Docker on your operating system (eg Docker Desktop on OSX)

#### Step 2 - Fork Turbinia
Fork Turbinia on Github and create a new feature branch to work on.
```
$ git clone https://github.com/[your-github-user-id]/turbinia.git
$ git remote add upstream https://github.com/google/turbinia.git
$ git checkout -b my-new-feature
$ cd turbinia
```

#### Step 3 - Open in Visual Studio Code
Open the folder in vscode and choose to "Reopen in Container" when asked (vscode will see the ```.devcontainer``` folder in the turbinia cloned source tree). Vscode will build your Turbinia development container and that will take a couple of minutes.

Note: if vscode does not ask you to reopen in a container you need to verify you have installed the Remote Development extension!

When this is finished continue with Step 4 for a local Turbinia setup or Step 6 for a GCP hybrid setup. 

#### Step 4 - Local Turbinia setup
The local turbinia setup will use redis and celery. Let's create the configuration file for this setup.
```
$ sed -f ./docker/vscode/redis-config.sed ./turbinia/config/turbinia_config_tmpl.py > ~/.turbiniarc
```

#### Step 5 - Local Turbinia verification
Let's verify that the local setup is working before we start developing and debugging. We are going to start a server and worker in seperate vscode terminals and create a Turbinia request in a third.. Open up 3 vscode terminals and execute below commands.

Start server
```
$ python3 turbinia/turbiniactl.py -S server
```
Start worker
```
$ python3 turbinia/turbiniactl.py -S celeryworker
```
Fetch and process some evidence
```
$ curl https://raw.githubusercontent.com/obsidianforensics/hindsight/master/tests/fixtures/profiles/60/History > History
$ tar -vzcf /evidence/history.tgz History
$ python3 turbinia/turbiniactl.py compresseddirectory -l /evidence/history.tgz 
$ python3 turbinia/turbiniactl.py status -r [request_id]
```

This should process the evidence and show output in each terminal for server and worker. Results will be stored in ```/evidence```.

You're done :). Go to Step 8 for a vscode debugging example.

#### Step 6 - GCP hybrid Turbinia setup
Follow the ‘GCP Setup’ section [here](https://turbinia.readthedocs.io/en/latest/user/install-manual.html) and setup Cloud Functions, a GCE bucket, Datastore and PubSub.
* Create a pubsub topic ,eg ‘turbinia-dev’.
* Create a GCE storage bucket with a unique name.
* Create the GCP Cloud Functions
```
$ git clone https://github.com/forseti-security/osdfir-infrastructure.git
$ cd osdfir-infrastructure
$ export TURBINIA_REGION=us-central1
$ gcloud -q functions deploy gettasks --region $TURBINIA_REGION --source modules/turbinia/data/ --runtime nodejs10 --trigger-http --memory 256MB --timeout 60s
$ gcloud -q functions deploy closetask --region $TURBINIA_REGION --source modules/turbinia/data/ --runtime nodejs10 --trigger-http --memory 256MB --timeout 60s
$ gcloud -q functions deploy closetasks  --region $TURBINIA_REGION --source modules/turbinia/data/ --runtime nodejs10 --trigger-http --memory 256MB --timeout 60s
```

Create the Turbinia hybrid configuration file.
```
sed -f ./docker/vscode/psq-config.sed ./turbinia/config/turbinia_config_tmpl.py > ~/.turbiniarc
```

Edit the configuration file ```~/.turbiniarc``` and set below variables according to the GCP project you are using. Make sure all values are between quotes!
```
TURBINIA_PROJECT = '[your_gcp_project_name]' 
TURBINIA_REGION = '[your_preferred_region]'  eg 'us-central1'
TURBINIA_ZONE = '[your_preferred_zone]'  eg 'us-central1-f'
PUBSUB_TOPIC = '[your_gcp_pubsub_topic_name]' eg 'turbinia-dev'
BUCKET_NAME = '[your_gcp_bucket_name]'
```

Setup authentication for the GCP project.
```
$ gcloud auth login
$ gcloud auth application-default login
```

#### Step 7 - GCP hybrid Turbinia verification
Let's verify that the GCP hybrid setup is working before we start developing and debugging. We are going to start a server and worker in seperate vscode terminals and create a Turbinia request in a third.. Open up 3 vscode terminals and execute below commands.

Terminal 1 - Start server
```
$ python3 turbinia/turbiniactl.py -S server
```
Terminal 2 - Start worker
```
$ python3 turbinia/turbiniactl.py -S psqworker
```
Terminal 3 - Fetch and process some evidence
```
$ curl https://raw.githubusercontent.com/obsidianforensics/hindsight/master/tests/fixtures/profiles/60/History > History
$ tar -vzcf /evidence/history.tgz History
$ python3 turbinia/turbiniactl.py compresseddirectory -l /evidence/history.tgz 
$ python3 turbinia/turbiniactl.py -a status -r [request_id]
```

This should process the evidence and show output in each terminal for server and worker. Results will be stored in ```/evidence``` and in the GCE bucket.

You're done :). Go to Step 8 for a vscode debugging example.

#### Step 8 - Debugging example
When you are developing code you want to be able to step through your code and inspect variables. We can do this by running the different launch profiles provided. Visual Studio Code launch profiles are provided for server, celeryworker, psqworker and client requests. 

As a small example we will change the version string of Turbinia.
* edit ```turbinia/__init__.py``` and change around line 24 the version string from "unknown" to "iamrad" (The person who wrote this is old...).
* set a breakpoint on the line you edited.
* save the file.
* we want to hit this code path while running the server so we will start the 'Turbinia Server' launch profile.
 * click on the 'Run' icon on the left hand side (*not* the menu at the top!).
 * choose the 'Turbinia Server' profile.
 * hit the green play button to start debugging.
* the server will start and vscode will break when it hits your edited version string.
* inspect the variables and step through your code at will.

It's important to understand that if you are developing and debugging more complex code paths that you will almost certainly run a combination of vscode terminal and vscode launch profile server/workers/client. You need to use the correct launch profile to hit the breakpoints depending on where you have set them.
