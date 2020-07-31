# FAQ


## Where do I specify configuration options?

Configuration can either go into `~/.turbiniarc` or `/etc/turbinia/turbinia.conf`

## Where are the configuration options documented?

The configuration options are documented in [turbinia_config_tmpl.py](
https://github.com/google/turbinia/blob/master/turbinia/config/turbinia_config_tmpl.py)

## How can I write new Tasks?

New Task development documentation can be [found here](
../developer/developing-new-tasks.md)

## How can I debug problems with Turbinia?

Information on debugging and other common errors can be [found here](
debugging.md)

## Where are the files listed in the turbiniactl status output?

Files with local paths listed in the output for `turbiniactl status` are local
to the Workers that ran that Task.  Files with paths starting with gs:// are
in the Google Cloud Storage bucket (as specified by `GCS_OUTPUT_PATH` in the
config).  Only Evidence types with the `copyable` property will actually be
copied into Cloud Storage.
