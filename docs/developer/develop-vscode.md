# Developing with Visual Studio Code (no cloud required)

## Introduction

This procedure will get you up and running with a Visual Studio Code environment for Turbinia development. The provided configuration files will create a development container containing all dependencies, pylint and yapf correctly setup and launch configurations for both client, server and workers. With this setup it is possible to initiate full Turbinia debug sessions including breakpoints, watches and stepping.

You can set Visual Studio Code up to run a local stack (using redis and celery) or use a hybrid GCP stack (using pubsub, datastore and cloud functions). We advice you to run a local stack if you don't need to debug or develop Turbinia GCP functionality.

## Before you start

- Check out the [How it Works](../user/how-it-works.md) page to see how the different
  components work within Turbinia.
- Make sure to follow the Turbinia
  [developer contribution guide](contributing.md).

#### Step 1 - Install required software

Prepare your OS:

- Install Visual Studio Code and install the Remote Development extension pack.
- Install Docker on your operating system (eg Docker Desktop on OSX)

#### Step 2 - Fork Turbinia

Fork Turbinia on Github and create a new feature branch to work on.

```
$ git clone https://github.com/[your-github-user-id]/turbinia.git
$ git remote add upstream https://github.com/google/turbinia.git
$ git checkout -b my-new-feature
$ cd turbinia
```

#### Step 3 - Open in Visual Studio Code

Open the folder in vscode and choose to "Reopen in Container" when asked (vscode will see the `.devcontainer` folder in the turbinia cloned source tree). Vscode will build your Turbinia development container and that will take a couple of minutes.

_Note_: If vscode does not ask you to reopen in a container you need to verify you have installed the Remote Development extension!

_Note_: The instructions contain shell commands to execute, please execute those commands in the vscode terminal (which runs in the development container) and not in a terminal on your host!

Continue with Step 4 for a local Turbinia setup or Step 6 for a GCP hybrid setup.

#### Step 4 - Local Turbinia setup

The local turbinia setup will use redis and celery. Let's create the configuration file for this setup.

_Note_: This command needs to be executed in the vscode terminal!

```
$ sed -f ./docker/vscode/redis-config.sed ./turbinia/config/turbinia_config_tmpl.py > ~/.turbiniarc
```

Let's verify the installation in Step 7.

#### Step 6 - GCP hybrid Turbinia setup

Follow the ‘GCP Setup’ section [here](https://turbinia.readthedocs.io/en/latest/user/install-manual.html) and setup Cloud Functions, a GCE bucket, Datastore and PubSub.

- Create a pubsub topic, eg ‘turbinia-dev’
- Create a GCE storage bucket with a unique name

Create the Turbinia hybrid configuration file.

_Note_: This command needs to be executed in the vscode terminal!

```
$ sed -f ./docker/vscode/psq-config.sed ./turbinia/config/turbinia_config_tmpl.py > ~/.turbiniarc
```

Edit the configuration file `~/.turbiniarc` and set below variables according to the GCP project you are using. Make sure all values are between quotes!

```
TURBINIA_PROJECT = '[your_gcp_project_name]'
TURBINIA_REGION = '[your_preferred_region]'  eg 'us-central1'
TURBINIA_ZONE = '[your_preferred_zone]'  eg 'us-central1-f'
PUBSUB_TOPIC = '[your_gcp_pubsub_topic_name]'  eg 'turbinia-dev'
BUCKET_NAME = '[your_gcp_bucket_name]'
```

Setup authentication for the GCP project.

_Note_: These commands need to be executed in the vscode terminal!

```
$ gcloud auth login
$ gcloud auth application-default login
```

Deploy the Google Cloud Functions

_Note_: This command needs to be executed in the vscode terminal!

```
$ PYTHONPATH=. python3 tools/gcf_init/deploy_gcf.py
```

#### Step 7 - Turbinia installation verification

Let's verify that the GCP hybrid setup is working before we start developing and debugging. We are going to start a server and worker in separate vscode terminals and create a Turbinia request in a third. Open up 3 vscode terminals and execute below commands.

_Note_: These commands need to be executed in the vscode terminal!

Terminal 1 - Start server

```
$ python3 turbinia/turbiniactl.py -S server
```

Terminal 2 - Start worker
For a local setup

```
$ python3 turbinia/turbiniactl.py -S celeryworker
```

For a GCP hybrid setup

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

This should process the evidence and show output in each terminal for server and worker. Results will be stored in `/evidence` and in the GCS bucket.

#### Step 8 - Debugging example

When you are developing code you want to be able to step through your code and inspect variables. We can do this by running the different launch profiles provided. Visual Studio Code launch profiles are provided for server, celeryworker, psqworker and client requests.

As a small example we will change the version string of Turbinia.

- Edit `turbinia/__init__.py` and change around line 24 the version string from "unknown" to "iamrad" (The person who wrote this is old...).
- Set a breakpoint on the line you edited.
- Save the file.
- We want to hit this code path while running the server so we will start the 'Turbinia Server' launch profile.
- Click on the 'Run' icon on the left hand side (_not_ the menu at the top!).
- Choose the 'Turbinia Server' profile.
- Hit the green play button to start debugging.
- The server will start and vscode will break when it hits your edited version string.
- Inspect the variables and step through your code at will.

It's important to understand that if you are developing and debugging more complex code paths that you will almost certainly run a combination of vscode terminal and vscode launch profile server/workers/client. You need to use the correct launch profile to hit the breakpoints depending on where you have set them.
