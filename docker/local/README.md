## Turbinia local stack using Docker
Turbinia can be run locally without any Cloud components using Docker. It will use Redis, Celery and local disk to store data and perform message broker functionality.

Detailed documentation and setup steps are available [here](https://turbinia.readthedocs.io/en/latest/user/turbinia-local-stack.html).

## Turbinia local stack with job dependecies in docker-in-docker
When you want to run the Job dependencies in a docker-in-docker (dind) engine, adust the DOCKER_ENABLED setting in the Turbinia configuration to `True` and use the `docker-compose-dind.yml` file with docker compose.