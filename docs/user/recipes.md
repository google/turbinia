### Recipes

#### Introduction
Recipes are a way to create pre-defined configurations for what Jobs/Tasks to
run and how to run them along with various parameters that Tasks can use to
change their runtime behavior for a given processing request.  They can contain
a number of "global" variables that affect the overall processing and also have
per-Task variables that are specific to each Task.

#### Using Recipes
Recipes can be specified by name when sending a processing request to Turbinia.
The name of the recipe is the filename that contains the recipe, which should
work with or without specifying the `.yaml` extension.
```
turbiniactl --recipe triage googleclouddisk -d diskname-to-process
```

Note: This currently requires that the `RECIPE_FILE_DIR` configuration variable
is set in the config file that you are using and is pointing to a valid
directory containing the [recipe
files](https://github.com/google/turbinia/tree/master/turbinia/config/recipes).
Alternately you can also specify a recipe file directly by referencing the file
path:
```
turbiniactl --recipe_path ./recipes/triage.yaml googleclouddisk -d diskname-to-process
```

#### Writing new Recipes
Recipes are `.yaml` files that are read and validated by the client and passed
to the server along with the processing request data.  There are no required
sections and they can contain a `globals` section and zero or more Task
sections.  Each Task section must contain a `task:` key that references the
relevant Task that the section applies to.  Other keys in either the `globals`
or Task sections must match the pre-defined keys for those sections.  Here is a
snapshot of the pre-defined variables allowed in the `globals` section along
with the defaults:
```
    'debug_tasks': False,
    'jobs_allowlist': [],
    'jobs_denylist': [],
    'yara_rules': '',
    'filter_patterns': [],
    'sketch_id': None
```

These generally correlate with similarly named command line flags.  The current
full list can be [found
here](https://github.com/google/turbinia/blob/8aafea5d4ba165aa72748ed7f1f196c8b9d7175c/turbinia/lib/recipe_helpers.py#L28).
Each Task specifies the available recipe keys in a `TASK_CONFIG` attribute for
the Task object (e.g. [here is the `TASK_CONFIG` for the Plaso
Task](https://github.com/google/turbinia/blob/8aafea5d4ba165aa72748ed7f1f196c8b9d7175c/turbinia/workers/plaso.py#L35)).


Here is a [real sample of the `all` Recipe](https://github.com/google/turbinia/blob/master/turbinia/config/recipes/all.yaml)
including the description in a comment:
```
# This recipe will run all Jobs with all configuration options turned on for in
# depth "kitchen-sink" processing of everything (e.g. all VSS stores and all
# partitions).  This may take a long time to complete.

globals:
  jobs_allowlist:
    - BinaryExtractorJob
    - BulkExtractorJob
    - FileSystemTimelineJob
    - FsstatJob
    - GrepJob
    - HadoopAnalysisJob
    - HindsightJob
    - HTTPAccessLogExtractionJob
    - HTTPAccessLogAnalysisJob
    - JenkinsAnalysisJob
    - JupyterExtractionJob
    - JupyterAnalysisJob
    - LinuxAccountAnalysisJob
    - PartitionEnumerationJob
    - PlasoJob
    - PsortJob
    - RedisAnalysisJob
    - RedisExtractionJob
    - SSHDAnalysisJob
    - SSHDExtractionJob
    - StringsJob
    - TomcatExtractionJob
    - TomcatAnalysisJob
    - WindowsAccountAnalysisJob

plaso_base:
  task: 'PlasoTask'
  status_view: 'none'
  hashers: 'all'
  partition: 'all'
  vss_stores: 'all'
```

For adding additional configuration options to a given Task, please see the
[recipes configuration section](../developer/developing-new-tasks.md) in the
developing new Tasks documentation.
