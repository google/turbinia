### Contributing

#### Before you contribute

We love contributions! Read this page (including the small print at the end).

Before we can use your code, you must sign the
[Google Individual Contributor License Agreement](https://developers.google.com/open-source/cla/individual?csw=1)
(CLA), which you can do online. The CLA is necessary mainly because you own the
copyright to your changes, even after your contribution becomes part of our
codebase, so we need your permission to use and distribute your code. We also
need to be sure of various other things—for instance that you'll tell us if you
know that your code infringes on other people's patents. You don't have to sign
the CLA until after you've submitted your code for review and a member has
approved it, but you must do it before we can put your code into our codebase.
Before you start working on a larger contribution, you should get in touch with
us first through the issue tracker with your idea so that we can help out and
possibly guide you. Coordinating up front makes it much easier to avoid
frustration later on.

We use the github
[fork and pull review process](https://docs.github.com/en/pull-requests/collaborating-with-pull-requests/proposing-changes-to-your-work-with-pull-requests/about-pull-requests)
to review all contributions. First, fork the Turbinia repository by following
the [github instructions](https://docs.github.com/en/get-started/quickstart/fork-a-repo).
Then check out your personal fork:

    $ git clone https://github.com/<username>/turbinia.git

Add an upstream remote so you can easily keep up to date with the main
repository:

    $ git remote add upstream https://github.com/google/turbinia.git

To update your local repo from the main:

    $ git pull upstream master

Please follow the Style Guide when making your changes, and also make sure to
use the project's
[pylintrc](https://github.com/google/turbinia/blob/master/.pylintrc)
and
[yapf config file](https://github.com/google/turbinia/blob/master/.style.yapf).
Once you're ready for review make sure the tests pass:

    $ pip install -e .[dev]
    $ pip install -r dfvfs_requirements.txt
    $ python ./run_tests.py


----
>  **_NOTE:_** If you are developing in a hybrid/local setup, you need to 
set the `PROMETHEUS_PORT` and `PROMETHEUS_ADDR` to `None` in your config file
in order to run Turbinia. 
----

Commit your changes to your personal fork and then use the GitHub Web UI to
create and send the pull request. We'll review and merge the change.

#### Code review

All submissions, including submissions by project members, require review. To
keep the code base maintainable and readable all code is developed using a
similar coding style. It ensures:

The code should be easy to maintain and understand. As a developer you'll
sometimes find yourself thinking hmm, what is the code supposed to do here. It
is important that you should be able to come back to code 5 months later and
still quickly understand what it supposed to be doing. Also for other people
that want to contribute it is necessary that they need to be able to quickly
understand the code. Be that said, quick-and-dirty solutions might work in the
short term, but we'll ban them from the code base to gain better long term
quality. With the code review process we ensure that at least two eyes looked
over the code in hopes of finding potential bugs or errors (before they become
bugs and errors). This also improves the overall code quality and makes sure
that every developer knows to (largely) expect the same coding style.

All Python code changes in the ```turbinia/api/client/``` directory can be
ignored during reviews. The API client library is auto-generated using
[OpenAPI Client Generator](https://github.com/OpenAPITools/openapi-generator).

#### Style guide

We primarily follow the
[Google Python Style Guide](https://google.github.io/styleguide/pyguide.html).
Various Turbinia specific additions/variations are:

*   Using two spaces instead of four
*   Quote strings as ' or """ instead of "
*   Exception variables should be named 'exception' not 'e'.
*   Use type annotations ("type hints") for newly created Python modules.
*   Use f-String formatting instead of the % operator or str.format().
*   Use positional or parameter format specifiers with typing e.g. '{0:s}' or
    '{text:s}' instead of '{0}', '{}' or '{:s}'. If we ever want to have
    language specific output strings we don't need to change the entire
    codebase. It also makes is easier in determining what type every parameter
    is expected to be.
*   Use "cls" as the name of the class variable in preference of "klass"
*   When catching exceptions use "as exception:" not some alternative form like
    "as error:" or "as details:"
*   Use textual pylint overrides e.g. "# pylint: disable=no-self-argument"
    instead of "# pylint: disable=E0213". For a list of overrides see:
    http://docs.pylint.org/features.html

#### Updating dependencies

If you are adding a new dependency or changing the version of a dependency:

*   Edit ```pyproject.toml``` with the new version for the dependency.
*   Run ```poetry lock``` to resolve any dependency conflicts. This will regenerate ```poetry.lock```.

#### Updating the API server endpoints and client library

If you are making changes to the API endpoints or adding new ones, make sure to
reflect the changes in the ```openapi.yaml``` specification file.

Once the updates are reflected in the ```openapi.yaml``` file, you can run the
OpenAPI generator docker container to update the API client library.

    $ docker pull openapitools/openapi-generator-cli:latest-release

    $ docker run --rm -v ${PWD}:/local openapitools/openapi-generator-cli:latest-release generate -i \
      /local/turbinia/api/openapi.yaml -g python-pydantic-v1 -o /local/turbinia/api/client \
      --additional-properties packageName=turbinia_api_lib

This will generate an update library in ```turbinia/api/client```.

Make sure to review and make any necessary changes to the ```pyproject.toml``` file
(e.g. the version number) and run ```poetry lock``` from the ```api/client``` directory when done.

#### The small print

Contributions made by corporations are covered by a different agreement than the
one above, the Software Grant and Corporate Contributor License Agreement.
