**Note**: **_This installation method will be deprecated by the end of 2022.
The current recommended method for installing Turbinia is
[here](install-gke-pubsub.md)._**

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
to automate deployment of Turbinia into an existing GCP Project.
for details.

## Installation

The following steps can be performed on any Linux machine (Ubuntu 18.0.4
recommended), and [Cloud Shell](https://cloud.google.com/shell/) is one easy way
to get a shell with access to your GCP resources.

### GCP Project Setup

- Create or select a Google Cloud Platform project in the
  [Google Cloud Console](https://console.cloud.google.com).
- Determine which GCP zone and region that you wish to deploy Turbinia into.
  Note that one of the GCP dependencies is Cloud Functions, and that only
  works in certain regions, so you will need to deploy in one of
  [the supported regions](https://cloud.google.com/functions/docs/locations).
- Install
  [google-cloud-sdk](https://cloud.google.com/sdk/docs/quickstart-linux).
  - Note: If you are doing this from cloud shell you shouldn't need this
    step.
- Run `gcloud auth login` to authenticate. This may require you to copy/paste
  url to browser.
- Run `gcloud auth application-default login`

### Deploy Turbinia

- Download the
  [Terraform CLI from here](https://www.terraform.io/downloads.html).
- Clone the Forseti Security repository and change to the path containing the
  configs
  - `git clone https://github.com/forseti-security/osdfir-infrastructure/`
  - `cd osdfir-infrastructure`
- Configuration

  - By default this will create one Turbinia server instance and one worker
    instance. If you want to change the number of workers, edit the
    `modules/turbinia/variables.tf` file and set the `turbinia_worker_count`
    variable to the number of workers you want to deploy.
  - To adjust the GCP zone and region you want to run Turbinia in, edit the
    `modules/turbinia/variables.tf` file and change the `gcp_zone` and
    `gcp_region` variables as appropriate to reflect your GCP project's
    zone and region.
  - If you want to use docker to run Turbinia tasks, please follow the
    instructions [here](using-docker.md) to enable docker.
  - Running the following commands will leave some state information under
    the current directory, so if you wish to continue to manage the number
    of workers via Terraform you should keep this directory for later use.
    Alternatively, if you wish to store this information in GCS instead, you
    can edit `main.tf` and change the `bucket` parameter to the GCS bucket
    you wish to keep this state information in. See the
    [Terraform documentation](https://developer.hashicorp.com/terraform/cli/commands)
    for more information.
  - The current configuration does not enable alert notifications by default.
    Please see [here](#grafana-smtp-setup) for the instructions
  - If you are running multiple workers on a given host and within containers, ensure
    that you are mapping the host `OUTPUT_DIR` path specified in the configuration file
    `.turbiniarc` to the containers so that they can properly update the `RESOURCE_STATE_FILE`.

- Initialize terraform and apply the configuration
  - `./deploy.sh --no-timesketch`
    - If the `--no-timesketch` parameter is not supplied, Terraform will also
      create a [Timesketch](http://timesketch.org) instance in the same
      project, and this can be configured to ingest Turbinia timeline
      output and report data. See the
      [Documentation on this](https://github.com/forseti-security/osdfir-infrastructure)
      for more details.
    - When prompted for the project name, enter the project you selected
      during setup.

This should result in the appropriate cloud services being enabled and
configured and GCE instances for the server and the worker(s) being started and
configured. The Turbinia configuration file will be deployed on these instances
as `etc/turbinia/turbinia.conf`. If you later want to increase the number of
workers, you can edit the `turbinia/variables.tf` file mentioned above and
re-run `terraform apply`
To use Turbinia you can use the virtual environment that was setup by
the `deploy.sh` script.To activate the virtual environment, run the following
command `source ~/turbinia/bin/activate` and then use `turbiniactl`. For more
information on how to use Turbinia please visit [the user manual](https://github.com/google/turbinia).

### Client configuration (optional)

If you want to use the command line tool, you can SSH into the server and run
`turbiniactl` from there. The `turbiniactl` command can be used to submit
Evidence for processing or see the status of existing and previous processing
requests. If you'd prefer to use turbiniactl on a different machine, follow the
following instructions to configure the client. The instructions are based on
using Ubuntu 18.04, though other versions of Linux should be compatible.

- Follow the steps from GCP Project setup above to install the SDK and
  authenticate with gcloud.
- Install some python tooling:
  - `apt-get install python3-pip python3-wheel`
- Install the Turbinia client.
  - Note: You may want to install this into a virtual-environment with
    [venv](https://docs.python.org/3.7/library/venv.html) or
    [pipenv](https://pipenv.pypa.io/en/latest/)) to reduce potential
    dependency conflicts and isolate these packages into their own
    environment.
  - `pip3 --user install turbinia`
- If running on the same machine you deployed Turbinia from, you can generate
  the config with terraform
  - `terraform output turbinia-config > ~/.turbiniarc`
- Otherwise, if you are running from a different machine you'll need to copy
  the Turbinia config from the original machine, or from the Turbinia server
  from `/etc/turbinia/turbinia.conf`.

### Grafana SMTP Setup

If you want to receive alert notifications from Grafana, you'll need to setup a SMTP server for Grafana. To configure a SMTP server, you need to add the following environment variables to `Grafana` `env` section in `osdfir-infrastructure/modules/monitoring/main.tf`

```
      {
        name = "GF_SMTP_ENABLED"
        value = "true"
      }, {
        name = "GF_SMTP_HOST"
        value = "smtp.gmail.com:465" # Replace this if you're not using gmail
      }, {
        name = "GF_SMTP_USER"
        value = "<EMAIL ADDRESS HERE>"
      }, {
        name = "GF_SMTP_PASSWORD"
        value = "<PASSWORD>"
      }, {
        name = "GF_SMTP_SKIP_VERIFY"
        value = "true"
      }, {
        name = "GF_SMTP_FROM_ADDRESS"
        value = "<EMAIL ADDRESS THAT SHOWS AS THE SENDER>"
      }

```

---

> **NOTE**

> By default Gmail does not allow [less secure apps](https://support.google.com/accounts/answer/6010255) to authenticate and send emails. For that reason, you'll need to allow less secure apps to access the provided Gmail account.

---

Once completed:

- login to the Grafana Dashboard.
- Select Alerting and choose "Notification channels".
- Fill the required fields and add the email addresses that will receive notification.
- Click "Test" to test your SMTP setup.
- Once everything is working, click "Save" to save the notification channel.
