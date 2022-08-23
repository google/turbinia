**Note**: ***This installation method will be deprecated by the end of 2022. 
The current recommended method for installing Turbinia is
[here](https://turbinia.readthedocs.io/en/latest/user/install-gke.html).***

# **Turbinia Quick Installation Instructions**

## Overview

Turbinia can be run on the [Google Cloud Platform](https://cloud.google.com), on
local machines, or in a hybrid mode. See the
"[how it works](how-it-works.md)"
documentation for more details on what the architecture looks like for each of
these installation types. This doc covers the recommended quick installation
instructions for Cloud installations. This uses
[terraform configs](https://github.com/forseti-security/osdfir-infrastructure)
that are part of the
[Forseti Security repository](https://github.com/forseti-security)
to automate deployment of Turbinia into an existing GCP Project. If you want to
install Turbinia in hybrid or local only mode, or want to install Turbinia
manually (not recommended), see
[here](install-manual.md)
for details.

## Installation

The following steps can be performed on any Linux machine (Ubuntu 18.0.4
recommended), and [Cloud Shell](https://cloud.google.com/shell/) is one easy way
to get a shell with access to your GCP resources.

### GCP Project Setup

*   Create or select a Google Cloud Platform project in the
    [Google Cloud Console](https://console.cloud.google.com).
*   Determine which GCP zone and region that you wish to deploy Turbinia into.
    Note that one of the GCP dependencies is Cloud Functions, and that only
    works in certain regions, so you will need to deploy in one of
    [the supported regions](https://cloud.google.com/functions/docs/locations).
*   Install
    [google-cloud-sdk](https://cloud.google.com/sdk/docs/quickstart-linux).
    *   Note: If you are doing this from cloud shell you shouldn't need this
        step.
*   Run `gcloud auth login` to authenticate. This may require you to copy/paste
    url to browser.
*   Run `gcloud auth application-default login`

### Deploy Turbinia

*   Download the
    [Terraform CLI from here](https://www.terraform.io/downloads.html).
*   Clone the Forseti Security repository and change to the path containing the
    configs
    *   `git clone https://github.com/forseti-security/osdfir-infrastructure/`
    *   `cd osdfir-infrastructure`
*   Configuration
    *   By default this will create one Turbinia server instance and one worker
        instance. If you want to change the number of workers, edit the
        `modules/turbinia/variables.tf` file and set the `turbinia_worker_count`
        variable to the number of workers you want to deploy.
    *   To adjust the GCP zone and region you want to run Turbinia in, edit the
        `modules/turbinia/variables.tf` file and change the `gcp_zone` and 
        `gcp_region` variables as appropriate to reflect your GCP project's
        zone and region.
    *   If you want to use docker to run Turbinia tasks, please follow the
        instructions [here](using-docker.md) to enable docker.
    *   Running the following commands will leave some state information under
        the current directory, so if you wish to continue to manage the number
        of workers via Terraform you should keep this directory for later use.
        Alternatively, if you wish to store this information in GCS instead, you
        can edit `main.tf` and change the `bucket` parameter to the GCS bucket
        you wish to keep this state information in. See the
        [Terraform documentation](https://www.terraform.io/docs/commands/index.html)
        for more information.
    *   The current configuration does not enable alert notifications by default.
        Please see [here](#grafana-smtp-setup) for the instructions
    *   If you are running multiple workers on a given host and within containers, ensure
        that you are mapping the host `OUTPUT_DIR` path specified in the configuration file 
        `.turbiniarc` to the containers so that they can properly update the `RESOURCE_STATE_FILE`.

*   Initialize terraform and apply the configuration
    *   `./deploy.sh --no-timesketch`
        *   If the `--no-timesketch` parameter is not supplied, Terraform will also
            create a [Timesketch](http://timesketch.org) instance in the same
            project, and this can be configured to ingest Turbinia timeline
            output and report data. See the
            [Documentation on this](https://github.com/forseti-security/osdfir-infrastructure)
            for more details.
        *   When prompted for the project name, enter the project you selected
            during setup.