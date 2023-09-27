.. role:: raw-rst(raw)
   :format: rst


Turbinia API CLI tool (turbinia-client)
=======================================

Summary
-------

Turbinia-client is a command-line tool that provides an easy-to-use user interface for Turbinia's API server. It allows a user to perform Turbinia operations such as creating new Turbinia processing requests, getting status of existing requests and tasks, and downloading requests output and logs.

Getting started
---------------

To get started with the Turbinia API CLI tool you will need to install it on your system. To install the tool, follow the instructions below.

Installation
^^^^^^^^^^^^

You can install the latest version of the tool via PyPi.

.. code-block::

   pip install turbinia-client

The package will install the ``turbinia-api-lib`` library as a dependency. More information on how to use the ``turbinia-api-lib`` Python library can be found `here <https://github.com/google/turbinia/tree/master/turbinia/api/client>`_.

Configuring the client
^^^^^^^^^^^^^^^^^^^^^^

The command-line tool uses a JSON configuration file. By default, the client will search for a ``.turbinia_api_config.json`` file within the user's home directory, or a path specified in the ``TURBINIA_API_CONFIG_PATH`` environment variable.

Support for multiple Turbinia environments is possible in the configuration file. In the example below, there are two Turbinia environments, ``default`` and ``development``.

.. code-block::

   {
       "default": {
           "description": "This file is used by turbinia-client to determine the location of the API server and if authentication will be used. These options should match your Turbinia deployment.",
           "comments": "By default, the credentials and client secrets files are located in the user's home directory.",
           "API_SERVER_ADDRESS": "http://localhost",
           "API_SERVER_PORT": 8000,
           "API_AUTHENTICATION_ENABLED": false,
           "CLIENT_SECRETS_FILENAME": ".client_secrets.json",
           "CREDENTIALS_FILENAME": ".credentials_default.json"
       },
       "development": {
           "description": "Development environment.",
           "API_SERVER_ADDRESS": "http://localhost",
           "API_SERVER_PORT": 8001,
           "API_AUTHENTICATION_ENABLED": false,
           "CLIENT_SECRETS_FILENAME": ".client_secrets_dev.json",
           "CREDENTIALS_FILENAME": ".credentials_dev.json"
       }
   }

A specific environment can be accessed by setting the ``TURBINIA_CONFIG_INSTANCE`` environment variable to a valid environment name from the configuration file or alternatively, via the ``-c`` argument. (e.g. ``turbinia-client -c development config list``\ )

Usage
^^^^^

You can view the help menu with the ``-h`` argument

.. code-block::

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

Getting the server configuration
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block::

   turbinia-client config list

Getting request or task information
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

To get the status of a Turbinia request:

.. code-block::

   turbinia-client status request <request_id>

For task status:

.. code-block::

   turbinia-client status task <task_id>

where ``<request_id>`` and ``<task_id>`` are the respective Turbinia request or task identifiers.

To get a summary of all existing requests:

.. code-block::

   turbinia-client status summary

Creating new requests
^^^^^^^^^^^^^^^^^^^^^

New Turbinia requests can be submitted via turbinia-client using the ``submit`` command. In its simplest form, you only need to pass the evidence type and any required arguments for the specific evidence type. As an example, to submit a new Turbinia request to process a ``RawDisk`` evidence type, run the following command:

.. code-block::

   turbinia-client submit rawdisk --source_path /evidence/rawdisk.dd

Each evidence type will have its own set of required and optional arguments. You can view all possible arguments with:

.. code-block::

   turbinia-client submit <evidence_type> -h

where ``<evidence_type>`` is a valid Turbinia evidence name.

A list of all valid Turbinia evidence names can be viewed with:

.. code-block::

   turbinia-client submit -h

Creating custom requests
^^^^^^^^^^^^^^^^^^^^^^^^

It is possible to customize requests with additional parameters. For example, you can provide your own Turbinia recipe and add it to a new Turbinia request as follows:

.. code-block::

   turbinia-client submit rawdisk --source_path /evidence/rawdisk.dd --recipe_name /home/user/my_triage_recipe.yaml --requester my_user --reason forensics_case_12345

An alternative way of providing a Turbinia recipe is to use the ``recipe_data`` argument. The ``recipe_data`` argument takes in a Base64 encoded string value of a valid Turbinia recipe.

.. code-block::

   turbinia-client submit rawdisk --source_path /evidence/rawdisk.dd --recipe_data <base64_encoded_recipe_content>

Getting Turbinia request or task output
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The ``result`` command can be used to download the output of a specific Turbinia request or task. The current version of the API server will return a ``.tgz`` of the contents of the request or task output directory. The ``.tgz`` file will also include task and worker log files.

.. code-block::

   turbinia-client result request <request_id>

.. code-block::

   turbinia-client result task <task_id>

By default, the downloaded file will be placed in the current working directory.

Getting JSON responses from the API server
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

By default, the tool will format the output from the API server to make it more human-readable. You can pass the ``-j`` argument to any command to print the API server's JSON response instead. For example:

.. code-block::

   turbinia-client status summary -j

Reporting bugs and contributing
-------------------------------

Please report any `bugs <https://github.com/google/turbinia/issues/new>`_ or submit `contributions <https://turbinia.readthedocs.io/en/latest/developer/contributing.html>`_ by following the instructions at the main Turbinia repository.
