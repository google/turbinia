# Turbinia

## Summary
Turbinia is an open-source framework for deploying, managing, and running forensic workloads on cloud platforms.  It is intended to automate running of common forensic processing tools (i.e. Plaso, TSK, strings, etc) to help with processing evidence in the Cloud, scaling the processing of large amounts of evidence, and decreasing response time by parallelizing processing where possible.

## How it works
Turbinia is composed of different components for the client, server and the workers.  These components can be run on local physical machines or in the Cloud.  The Turbinia client makes requests to process evidence to the Turbinia server.  The Turbinia server creates logical jobs from these incoming user requests, which creates and schedules forensic processing tasks to be run by the workers.  The evidence to be processed will be split up by the jobs when possible, and many tasks can be created in order to process the evidence in parallel.  One or more workers run continuously to process tasks from the server.  Any new evidence created or discovered by the tasks will be fed back into Turbinia for further processing.

Communication from the client to the server is currently done transparently with Google Cloud PubSub.  The worker implementation uses [PSQ](https://github.com/GoogleCloudPlatform/psq) (a Google Cloud PubSub Task Queue) for task scheduling.

## Status
Turbinia is still pre-Alpha.  There is currently a [GitHub Milestone](https://github.com/google/turbinia/milestone/1) tracking the remaining items for the Alpha release.  It was mostly re-written since the initial proof of concept, so some things may be broken at this time.

## Installation
There is an [extremely rough installation guide](docs/install.md), but it needs to be [updated and fixed up](https://github.com/google/turbinia/issues/23).

## Usage
The basic steps to get things running after the initial installation and configuration are:
* Start Turbinia server component with ```turbiniactl server``` command
* Start one or more Turbinia workers with ```turbiniactl psqworker```
* Send evidence to be processed from the turbinia client with ```turbiniactl ${evidencetype}```
* Check status of running tasks with ```turbiniactl status```

turbiniactl can be used to start the different components, and here is the basic usage:
```
$ ./turbiniactl -h
usage: turbiniactl [-h] [-q] [-v] [-d] [-a] [-o OUTPUT_DIR] [-L LOG_FILE] [-S]
                   [-V] [-D] [-w]
                   <command> ...

optional arguments:
  -h, --help            show this help message and exit
  -q, --quiet           Show minimal output
  -v, --verbose         Show verbose output
  -d, --debug           Show debug output
  -a, --all_fields      Show all task status fields in output
  -o OUTPUT_DIR, --output_dir OUTPUT_DIR
                        Directory path for output
  -L LOG_FILE, --log_file LOG_FILE
                        Log file
  -S, --server          Run Turbinia Server indefinitely
  -V, --version         Show the version
  -D, --dump_json       Dump JSON output of Turbinia Request instead of
                        sending it
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

## Notes
* Turbinia currently assumes that Evidence is equally available to all worker nodes (e.g. through locally mapped storage, or through attachable persistent Google Cloud Disks, etc).
* Not all evidence types are supported yet
* Still only a small number of processing job types supported, but more are being developed.

##### Obligatory Fine Print
This is not an official Google product (experimental or otherwise), it is just code that happens to be owned by Google.
