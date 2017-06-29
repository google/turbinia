# Turbinia

## Summary
Turbinia is an open-source framework for deploying, managing, and running forensic workloads on cloud platforms.

## How it works
Turbinia has different components for the client, server and the workers.  The Turibnia client makes requests to process evidence to the Turbinia server.  The Turbinia server is a single process that runs (on a cloud instance or a physical machine) and processes incoming user requests and then schedules forensic processing jobs to be processed by the workers.  The workers run on multiple cloud instances or physical machines continuously to process requests from the Server.   

## Status
Turbinia is still considered pre-Alpha.  There is currently a [GitHub Milestone](https://github.com/google/turbinia/milestone/1) tracking the remaining items for the Alpha release.  It was mostly re-written since the initial proof of concept, so some things may be broken at this time.

## Instalation
There is an [extremly rough installation guide](https://github.com/google/turbinia/wiki/Installation), but it definitely needs updating.

## Usage
Turbinia has different commands to run the different components of Turbinia.
```
$ ./turbiniactl -h
usage: turbiniactl [-h] [-v] [-d] [-o OUTPUT_DIR] [-L LOG_FILE] [-S] [-V]
                   <command> ...

optional arguments:
  -h, --help            show this help message and exit
  -v, --verbose         verbose
  -d, --debug           debug
  -o OUTPUT_DIR, --output_dir OUTPUT_DIR
                        Directory path for output
  -L LOG_FILE, --log_file LOG_FILE
                        Log file
  -S, --server          Run Turbinia Server indefinitely
  -V, --version         Show the version

Commands:
  <command>
    rawdisk             Process RawDisk as Evidence
    directory           Process a directory as Evidence
    listjobs            List all available jobs
    psqworker           Run PSQ worker
    server              Run Turbinia Server
```

The commands for processing the evidence types of rawdisk and directory specify information about evidence that Turbinia should process. By default, when adding new evidence to be processed will act as a client and send a request to the configured Turbinia server, otherwise if ```--server``` is specified, it will start up it's own Turbinia Server process.  Here's a help listing for a raw disk type of evidence to be processed by Turibnia:
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

##### Obligatory Fine Print
This is not an official Google product (experimental or otherwise), it is just code that happens to be owned by Google.
