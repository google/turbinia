# Turbinia
![Unit tests](https://github.com/google/turbinia/actions/workflows/actions.yml/badge.svg) ![e2e tests](https://github.com/google/turbinia/actions/workflows/e2e.yml/badge.svg)

## Summary

Turbinia is an open-source framework for deploying, managing, and running
distributed forensic workloads. It is intended to automate running of common
forensic processing tools (i.e. Plaso, TSK, strings, etc) to help with
processing evidence in the Cloud, scaling the processing of large amounts of
evidence, and decreasing response time by parallelizing processing where
possible.

<img src="docs/images/turbinia-logo.jpg?raw=true" width=240>

## How it works

Turbinia is composed of different components for the client, server and the
workers. These components can be run in the Cloud, on local machines, or as a
hybrid of both. The Turbinia client makes requests to process evidence to the
Turbinia server. The Turbinia server creates logical jobs from these incoming
user requests, which creates and schedules forensic processing tasks to be run
by the workers. The evidence to be processed will be split up by the jobs when
possible, and many tasks can be created in order to process the evidence in
parallel. One or more workers run continuously to process tasks from the server.
Any new evidence created or discovered by the tasks will be fed back into
Turbinia for further processing.

Communication from the client to the server is currently done with 
[Kombu](https://github.com/celery/kombu) messaging. The worker implementation uses 
[Celery](http://www.celeryproject.org/) for task scheduling.

The main documentation for Turbinia can be
[found here](https://turbinia.readthedocs.io/). You can also find out more about
the architecture and
[how it works here](https://turbinia.readthedocs.io/en/latest/user/how-it-works.html).

## Status

Turbinia is currently in Alpha release.

## Installation

There is an
[installation guide here](https://turbinia.readthedocs.io/en/latest/user/install.html).

## Usage

The basic steps to get things running after the initial installation and
configuration are:

*   Start Turbinia server component with `turbiniactl server` command
*   Start Turbinia API server component with `turbiniactl api_server` command if using Celery
*   Start one or more Turbinia workers with `turbiniactl celeryworker`
*   Install `turbinia-client` via `pip install turbinia-client`
*   Send evidence to be processed from the turbinia client with `turbinia-client submit ${evidencetype}`
*   Check status of running tasks with `turbinia-client status`

turbinia-client can be used to interact with Turbinia through the API server component, and here is the basic
usage:

```
$ turbinia-client -h
Usage: turbinia-client [OPTIONS] COMMAND [ARGS]...

  Turbinia API command-line tool (turbinia-client).

                          ***    ***
                           *          *
                      ***             ******
                     *                      *
                     **      *   *  **     ,*
                       *******  * ********
                              *  * *
                              *  * *
                              %%%%%%
                              %%%%%%
                     %%%%%%%%%%%%%%%       %%%%%%
               %%%%%%%%%%%%%%%%%%%%%      %%%%%%%
  %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%  ** *******
  %%                                                   %%  ***************
  %%                                (%%%%%%%%%%%%%%%%%%%  *****  **
    %%%%%        %%%%%%%%%%%%%%%
    %%%%%%%%%%                     %%          **             ***
       %%%                         %%  %%             %%%           %%%%,
       %%%      %%%   %%%   %%%%%  %%%   %%%   %%  %%%   %%%  %%%       (%%
       %%%      %%%   %%%  %%%     %%     %%/  %%  %%%   %%%  %%%  %%%%%%%%
       %%%      %%%   %%%  %%%     %%%   %%%   %%  %%%   %%%  %%% %%%   %%%
       %%%        %%%%%    %%%       %%%%%     %%  %%%    %%  %%%   %%%%%

  This command-line tool interacts with Turbinia's API server.

  You can specify the API server location in ~/.turbinia_api_config.json

Options:
  -c, --config_instance TEXT  A Turbinia instance configuration name.
                              [default: (dynamic)]
  -p, --config_path TEXT      Path to the .turbinia_api_config.json file..
                              [default: (dynamic)]
  -h, --help                  Show this message and exit.

Commands:
  config    Get Turbinia configuration.
  evidence  Get or upload Turbinia evidence.
  jobs      Get a list of enabled Turbinia jobs.
  result    Get Turbinia request or task results.
  status    Get Turbinia request or task status.
  submit    Submit new requests to the Turbinia API server.
```

Check out the `turbinia-client` documentation [page](https://turbinia.readthedocs.io/en/latest/user/turbinia-client.html#turbinia-api-cli-tool-turbinia-client) for a detailed user guide.

You can also interact with Turbinia directly from Python by using the API library. We provide some examples [here](https://github.com/google/turbinia/tree/master/turbinia/api/client)

## Other documentation

*   [Main Documentation](https://turbinia.readthedocs.io)
*   [Installation](https://turbinia.readthedocs.io/en/latest/user/install.html)
*   [How it works](https://turbinia.readthedocs.io/en/latest/user/how-it-works.html)
*   [Operational Details](https://turbinia.readthedocs.io/en/latest/user/operational-details.html)
*   [Turbinia client CLI tool](https://turbinia.readthedocs.io/en/latest/user/turbinia-client.html#turbinia-api-cli-tool-turbinia-client)
*   [Turbinia API server](https://turbinia.readthedocs.io/en/latest/user/api-server.html)
*   [Turbinia Python API library](https://github.com/google/turbinia/tree/master/turbinia/api/client)
*   [Contributing to Turbinia](https://turbinia.readthedocs.io/en/latest/developer/contributing.html)
*   [Developing new Tasks](https://turbinia.readthedocs.io/en/latest/developer/developing-new-tasks.html)
*   [FAQ](https://turbinia.readthedocs.io/en/latest/user/faq.html)
*   [Debugging and Common Errors](https://turbinia.readthedocs.io/en/latest/user/debugging.html)
*   [Using Docker to execute jobs](https://turbinia.readthedocs.io/en/latest/user/using-docker.html)

##### Obligatory Fine Print

This is not an official Google product (experimental or otherwise), it is just
code that happens to be owned by Google.
