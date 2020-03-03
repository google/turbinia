# Using Docker for job execution

## Overview 
Turbinia can support Docker by allowing users to configure jobs to execute through a Docker container. This eliminates the need to install all the necessary dependencies and/or external programs on the host machine and instead execute the job through a container that has all the necessary dependencies installed. Please note that Turbinia does not provide the Docker images necessary for each job and they will need to either be created or pulled from a container registry. 

## Enabling Docker usage
In order to enable this feature, please take the following steps. 
1. Install the Docker daemon on the host machine. Please visit the Docker website for the [Installation Guide](https://docs.docker.com/install/).
2. In the `.turbiniarc` configuration file, set the `DOCKER_ENABLED` flag to `True` to enable the usage of Docker. 
3. Review the `DEPENDENCIES` flag in the `.turbiniarc` configuration file and identify which job you would like to execute a Docker container for. Once identified, replace the value for `docker_image` with the `image_id` of the Docker image. 
4. Save the `.turbiniarc` configuration file then start a new worker.
5. If the dependency check succeeds, the worker should now execute the configured job through a Docker container. 
6. If you no longer would like to use the Docker image, set the `docker_image` value back to `None`.

## Example using Plaso
The following section provides an example of the steps mentioned above for the Plaso job by using the Docker CLI to retrieve the required information.
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
4. Identify the `DEPENDENICES` attribute and look for the job `PlasoJob`, then replace the `docker_image` value with the identified `IMAGE ID`. 
    ```python
    {
        'job': 'PlasoJob'
        'programs': ['log2timeline.py'],
        'docker_image': '9c22665bff50' 
    }
    ```
5. Save the configuration file, then restart the turbinia worker.
    * `turbiniactl psqworker`
6. If the dependency check succeeds, the worker should now execute the `PlasoJob` through the specified docker container.
