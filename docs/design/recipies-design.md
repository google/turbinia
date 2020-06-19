# Turbinia Recipes Design

## Objective

We want to be able to provide runtime configuration options to Turbinia that
configure how and which Tasks are run. We also want to be able to collect these
options in recipes that can be referred to and run by name.

## Background

Currently Turbinia runs with a mostly static configuration, and so we run the
same set of Tasks and the same set of arguments for those Tasks. We would like
to be able to change the behavior of a given Turbinia run by passing this kind
of data in as a recipe. This would allow us to specify more targeted processing
and analysis for various scenarios.

The default Turbinia processing run can take a long time because it will run
every single Task and the default Task configurations will also process
everything. This means it can take some time before we get useful results back.
A recipe for “Quick Triage” would be handy to limit the Turbinia Tasks and to
specify a more targeted set of Forensic Artifacts and parsers for Plaso in order
to provide a quick response. This could be executed in parallel with the longer
running Turbinia run with the full configuration.

## Requirements and Scale

*   Tasks should have a defined interface for possible configuration options
    along with their defaults
*   Recipes should be defined in code and checked in
*   Turbinia clients (e.g. dfTimewolf) can pass in recipes at run time
*   The recipe should be specifiable by name at run time

## Design Ideas

There are two components of this to make it work. Dynamic Task configuration and
Recipes.

## Dynamic Task Configuration

Tasks will define the configuration options that it can use at run time. This is
just a flat dict of options set in the Task object code. Only the options found
there can be configured dynamically by users. The values set in config will be
the defaults that are used by the Task when no overriding config is specified.

Here is an example of what PlasoTask.config could look like:

```
{
 'artifacts_list': ['MyDefaultArtifactName']
 'parsers_list': []
}
```

These options can also be used to dynamically generate command line option flags
so users can specify those when making Turbinia requests.

## Recipes

Recipes are a collection of these dynamic config options and some other global
config options. They are implemented as a dict with the global options (e.g.
`jobs_allowlist`) and a mapping of Task names to dicts of configuration options
we want to specify for those Tasks. These configuration options must correspond
to options that the Task itself exports in the TurbiniaTask.config attribute.

These recipes will be in a file per recipe, with the filename prefix being the
name of the recipe. All recipes are loaded by Turbinia when it starts. Users of
the CLI can specify a recipe to run by name, and Turbinia will pass in these
options to the tasks as they are run.

Because all of the options that can be specified by a recipe can also be
specified by CLI (`turbiniactl`) options, we don’t need to allow the user to
(directly) specify arbitrary recipe data structures. We can potentially allow
them to provide a recipe file that can be read and passed in as the recipe for
the given request. Another possibility could be for the command line flags to
override the options configured in a given recipe.

Here is an example of what a recipe could look like. This would exist in a file
similar to `quick-triage.recipe.json`. This is just one example, but we could
also implement this with YAML files, which might be a little easier to read and
configure.

```
{'task_config': {'plaso': {'artifacts_list': ['art1', 'art2'],
                           'parsers_list': ['foo', 'bar']},
                 'strings': {'context': True}},
 'patterns_list': ['my-keyword1', 'my-keyword2'],
 'jobs_allowlist': [],
 'jobs_denylist': ['MyCrazyLongRunningJob'],
}
```

Having no configuration options for some Tasks does not mean that the other
Jobs/Tasks will not be run. The global `jobs_allowlist` and `jobs_denylist`
options (only one can be specified at a time) will be used to control which Jobs
are run.

Alternate clients (e.g. dfTimewolf) can pass in a recipe dictionary in the
TurbiniaRequest object that is created. Any options that are not listed in the
config exported by the task will be ignored and not passed into the Task.

## Alternatives Considered

*   Passing around arbitrary dict objects that Tasks can read configuration data
    from. This could cause maintenance and other issues without a defined
    interface between the Tasks and the configuration.
