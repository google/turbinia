# Using Docker for Job execution

## Overview 
Turbinia supports the use of Docker by allowing a Task to execute its command through a Docker Container instead. For example, when a Task for a PlasoJob is passed to a Worker, the Task will execute the command `log2timeline.py <ARGS>` through the Container and pass back the associated data to the Worker for further processing. The benefit being that it eliminates having to install the required dependencies and/or external programs for a Job on the Worker's host machine. Please note that Turbinia does not provide the Docker Images necessary for each Job and they will need to either be created or pulled from a container registry.

## Enabling Docker usage
In order to enable this feature, please take the following steps. 
1. Install the Docker daemon on the Worker's host machine. Please visit the Docker website for the [Installation Guide](https://docs.docker.com/install/).
2. In the `.turbiniarc` configuration file, set the `DOCKER_ENABLED` flag to `True` to enable the usage of Docker. 
3. Review the `DEPENDENCIES` flag in the `.turbiniarc` configuration file and identify which Job you would like to execute a Docker container for. Once identified, replace the value for `docker_image` with the `image_id` of the Docker image. 
4. Save the `.turbiniarc` configuration file then restart all Workers for the changes to take into effect. 
5. When the Workers start, they will perform dependency checks to ensure that the binaries required by the Job are installed in the Container, and if that check passes, it will execute those in the configured Docker Container. 
6. If you no longer would like to use the Docker image, set the `docker_image` value back to `None`.

## Example using Plaso
The following section provides an example of the steps mentioned above for the Plaso Job by using the Docker CLI to retrieve the required information.
1. Retrieve the latest Plaso Docker image either locally or through a preconfigured registry containing the image.
    * ` docker pull log2timeline/plaso`
2. Identify the  `image_id` for the retrieved image. 
    * `docker image ls`  

    Then copy the value listed under the column `IMAGE ID`.
    ```
    REPOSITORY                                      TAG                 IMAGE ID            CREATED             SIZE
    log2timeline/plaso                              latest              9c22665bff50        4 days ago          314MB
    ```
3. Open up the `.turbiniarc` configuration file then set the attribute `DOCKER_ENABLED` to `True`. 
4. Identify the `DEPENDENICES` attribute and look for the Job `PlasoJob`, then replace the `docker_image` value with the identified `IMAGE ID`. 
    ```python
    {
        'job': 'PlasoJob'
        'programs': ['log2timeline.py'],
        'docker_image': '9c22665bff50' 
    }
    ```
5. Save the configuration file, then restart the turbinia Worker.
    * `sudo systemctl restart turbinia@psqworker.service`
6. If the dependency check succeeds, once a Worker receives a Docker configured Task, the Task will execute its external command through the Docker Container instead and pass the associated data back to the Worker for further processing. 
