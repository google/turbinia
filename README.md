# Turbinia

## Summary
Turbinia is an open-source framework for deploying, managing, and running distributed forensic workloads.  It is intended to automate running of common forensic processing tools (i.e. Plaso, TSK, strings, etc) to help with processing evidence in the Cloud, scaling the processing of large amounts of evidence, and decreasing response time by parallelizing processing where possible.

<img src="docs/images/turbinia-logo.jpg?raw=true" width=240>

## How it works
Turbinia is composed of different components for the client, server and the workers.  These components can be run in the Cloud, on local machines, or as a hybrid of both.  The Turbinia client makes requests to process evidence to the Turbinia server.  The Turbinia server creates logical jobs from these incoming user requests, which creates and schedules forensic processing tasks to be run by the workers.  The evidence to be processed will be split up by the jobs when possible, and many tasks can be created in order to process the evidence in parallel.  One or more workers run continuously to process tasks from the server.  Any new evidence created or discovered by the tasks will be fed back into Turbinia for further processing.

Communication from the client to the server is currently done with either Google Cloud PubSub or [Kombu](https://github.com/celery/kombu) messaging.  The worker implementation can use either [PSQ](https://github.com/GoogleCloudPlatform/psq) (a Google Cloud PubSub Task Queue) or [Celery](http://www.celeryproject.org/) for task scheduling.

More information on Turbinia and how it works can be [found here](docs/how-it-works.md).

## Status
Turbinia is currently in Alpha release.

## Installation
There is an [rough installation guide here](docs/install.md).

## Usage
The basic steps to get things running after the initial installation and configuration are:
* Start Turbinia server component with ```turbiniactl server``` command
* Start one or more Turbinia workers with ```turbiniactl psqworker```
* Send evidence to be processed from the turbinia client with ```turbiniactl ${evidencetype}```
* Check status of running tasks with ```turbiniactl status```

turbiniactl can be used to start the different components, and here is the basic usage:
``` 
$ turbiniactl --help
usage: turbiniactl [-h] [-q] [-v] [-d] [-a] [-f] [-o OUTPUT_DIR] [-L LOG_FILE]
                   [-r REQUEST_ID] [-R] [-S] [-C] [-V] [-D]
                   [-F FILTER_PATTERNS_FILE] [-j JOBS_WHITELIST]
                   [-J JOBS_BLACKLIST] [-p POLL_INTERVAL] [-t TASK] [-w]
                   <command> ...

optional arguments:
  -h, --help            show this help message and exit
  -q, --quiet           Show minimal output
  -v, --verbose         Show verbose output
  -d, --debug           Show debug output
  -a, --all_fields      Show all task status fields in output
  -f, --force_evidence  Force evidence processing request in potentially
                        unsafe conditions
  -o OUTPUT_DIR, --output_dir OUTPUT_DIR
                        Directory path for output
  -L LOG_FILE, --log_file LOG_FILE
                        Log file
  -r REQUEST_ID, --request_id REQUEST_ID
                        Create new requests with this Request ID
  -R, --run_local       Run completely locally without any server or other
                        infrastructure. This can be used to run one-off Tasks
                        to process data locally.
  -S, --server          Run Turbinia Server indefinitely
  -C, --use_celery      Pass this flag when using Celery/Kombu for task
                        queuing and messaging (instead of Google PSQ/pubsub)
  -V, --version         Show the version
  -D, --dump_json       Dump JSON output of Turbinia Request instead of
                        sending it
  -F FILTER_PATTERNS_FILE, --filter_patterns_file FILTER_PATTERNS_FILE
                        A file containing newline separated string patterns to
                        filter text based evidence files with (in extended
                        grep regex format). This filtered output will be in
                        addition to the complete output
  -j JOBS_WHITELIST, --jobs_whitelist JOBS_WHITELIST
                        A whitelist for Jobs that we will allow to run (note
                        that it will not force them to run).
  -J JOBS_BLACKLIST, --jobs_blacklist JOBS_BLACKLIST
                        A blacklist for Jobs we will not allow to run
  -p POLL_INTERVAL, --poll_interval POLL_INTERVAL
                        Number of seconds to wait between polling for task
                        state info
  -t TASK, --task TASK  The name of a single Task to run locally (must be used
                        with --run_local.
  -w, --wait            Wait to exit until all tasks for the given request
                        have completed

Commands:
  <command>
    rawdisk             Process RawDisk as Evidence
    googleclouddisk     Process Google Cloud Persistent Disk as Evidence
    googleclouddiskembedded
                        Process Google Cloud Persistent Disk with an embedded
                        raw disk image as Evidence
    directory           Process a directory as Evidence
    listjobs            List all available jobs
    psqworker           Run PSQ worker
    celeryworker        Run Celery worker
    status              Get Turbinia Task status
    server              Run Turbinia Server
```

The commands for processing the evidence types of rawdisk and directory specify information about evidence that Turbinia should process. By default, when adding new evidence to be processed, turbiniactl will act as a client and send a request to the configured Turbinia server, otherwise if ```--server``` is specified, it will start up its own Turbinia server process.  Here's the turbiniactl usage for adding a raw disk type of evidence to be processed by Turbinia:
```
$ ./turbiniactl rawdisk -h
usage: turbiniactl rawdisk [-h] -l LOCAL_PATH [-s SOURCE] [-n NAME]

optional arguments:
  -h, --help            show this help message and exit
  -l LOCAL_PATH, --local_path LOCAL_PATH
                        Local path to the evidence
  -s SOURCE, --source SOURCE
                        Description of the source of the evidence
  -n NAME, --name NAME  Descriptive name of the evidence
```

## Other documentation
* [Installation](docs/install.md)
* [How it works](docs/how-it-works.md)
* [Contributing to Turbinia](docs/contributing.md)
* [Developing new Tasks](docs/developing-new-tasks.md)
* [FAQ](docs/faq.md)
* [Debugging and Common Errors](docs/debugging.md)


## Notes
* Turbinia currently assumes that Evidence is equally available to all worker nodes (e.g. through locally mapped storage, or through attachable persistent Google Cloud Disks, etc).
* Not all evidence types are supported yet
* Still only a small number of processing job types supported, but more are being developed.

##### Obligatory Fine Print
This is not an official Google product (experimental or otherwise), it is just code that happens to be owned by Google.
