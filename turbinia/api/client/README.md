# turbinia-api-lib
Turbinia is an open-source framework for deploying, managing, and running distributed forensic workloads

This Python package is automatically generated by the [OpenAPI Generator](https://openapi-generator.tech) project:

- API version: 1.0.0
- Package version: 1.0.0
- Build package: org.openapitools.codegen.languages.PythonClientCodegen

## Requirements.

Python 3.7+

## Installation & Usage
### pip install

If the python package is hosted on a repository, you can install directly using:

```sh
pip install git+https://github.com/GIT_USER_ID/GIT_REPO_ID.git
```
(you may need to run `pip` with root permission: `sudo pip install git+https://github.com/GIT_USER_ID/GIT_REPO_ID.git`)

Then import the package:
```python
import turbinia_api_lib
```

### Setuptools

Install via [Setuptools](http://pypi.python.org/pypi/setuptools).

```sh
python setup.py install --user
```
(or `sudo python setup.py install` to install the package for all users)

Then import the package:
```python
import turbinia_api_lib
```

### Tests

Execute `pytest` to run the tests.

## Getting Started

Please follow the [installation procedure](#installation--usage) and then run the following:

```python

import time
import turbinia_api_lib
from turbinia_api_lib.rest import ApiException
from pprint import pprint

# Defining the host is optional and defaults to http://localhost
# See configuration.py for a list of all supported configuration parameters.
configuration = turbinia_api_lib.Configuration(
    host = "http://localhost"
)

# The client must configure the authentication and authorization parameters
# in accordance with the API server security policy.
# Examples for each auth method are provided below, use the example that
# satisfies your auth use case.

configuration.access_token = os.environ["ACCESS_TOKEN"]


# Enter a context with an instance of the API client
with turbinia_api_lib.ApiClient(configuration) as api_client:
    # Create an instance of the API class
    api_instance = turbinia_api_lib.TurbiniaConfigurationApi(api_client)

    try:
        # Get Request Options
        api_response = api_instance.get_request_options()
        print("The response of TurbiniaConfigurationApi->get_request_options:\n")
        pprint(api_response)
    except ApiException as e:
        print("Exception when calling TurbiniaConfigurationApi->get_request_options: %s\n" % e)

```

## Documentation for API Endpoints

All URIs are relative to *http://localhost*

Class | Method | HTTP request | Description
------------ | ------------- | ------------- | -------------
*TurbiniaConfigurationApi* | [**get_request_options**](docs/TurbiniaConfigurationApi.md#get_request_options) | **GET** /api/config/request_options | Get Request Options
*TurbiniaConfigurationApi* | [**read_config**](docs/TurbiniaConfigurationApi.md#read_config) | **GET** /api/config/ | Read Config
*TurbiniaEvidenceApi* | [**get_evidence_attributes**](docs/TurbiniaEvidenceApi.md#get_evidence_attributes) | **GET** /api/evidence/types/{evidence_type} | Get Evidence Attributes
*TurbiniaEvidenceApi* | [**get_evidence_by_id**](docs/TurbiniaEvidenceApi.md#get_evidence_by_id) | **GET** /api/evidence/{evidence_id} | Get Evidence By Id
*TurbiniaEvidenceApi* | [**get_evidence_summary**](docs/TurbiniaEvidenceApi.md#get_evidence_summary) | **GET** /api/evidence/summary | Get Evidence Summary
*TurbiniaEvidenceApi* | [**get_evidence_types**](docs/TurbiniaEvidenceApi.md#get_evidence_types) | **GET** /api/evidence/types | Get Evidence Types
*TurbiniaEvidenceApi* | [**query_evidence**](docs/TurbiniaEvidenceApi.md#query_evidence) | **GET** /api/evidence/query | Query Evidence
*TurbiniaEvidenceApi* | [**upload_evidence**](docs/TurbiniaEvidenceApi.md#upload_evidence) | **POST** /api/evidence/upload | Upload Evidence
*TurbiniaJobsApi* | [**read_jobs**](docs/TurbiniaJobsApi.md#read_jobs) | **GET** /api/jobs/ | Read Jobs
*TurbiniaLogsApi* | [**get_logs**](docs/TurbiniaLogsApi.md#get_logs) | **GET** /api/logs/{query} | Get Logs
*TurbiniaRequestResultsApi* | [**get_request_output**](docs/TurbiniaRequestResultsApi.md#get_request_output) | **GET** /api/result/request/{request_id} | Get Request Output
*TurbiniaRequestResultsApi* | [**get_task_output**](docs/TurbiniaRequestResultsApi.md#get_task_output) | **GET** /api/result/task/{task_id} | Get Task Output
*TurbiniaRequestsApi* | [**create_request**](docs/TurbiniaRequestsApi.md#create_request) | **POST** /api/request/ | Create Request
*TurbiniaRequestsApi* | [**get_request_status**](docs/TurbiniaRequestsApi.md#get_request_status) | **GET** /api/request/{request_id} | Get Request Status
*TurbiniaRequestsApi* | [**get_requests_summary**](docs/TurbiniaRequestsApi.md#get_requests_summary) | **GET** /api/request/summary | Get Requests Summary
*TurbiniaTasksApi* | [**get_task_statistics**](docs/TurbiniaTasksApi.md#get_task_statistics) | **GET** /api/task/statistics | Get Task Statistics
*TurbiniaTasksApi* | [**get_task_status**](docs/TurbiniaTasksApi.md#get_task_status) | **GET** /api/task/{task_id} | Get Task Status
*TurbiniaTasksApi* | [**get_workers_status**](docs/TurbiniaTasksApi.md#get_workers_status) | **GET** /api/task/workers | Get Workers Status


## Documentation For Models

 - [BaseRequestOptions](docs/BaseRequestOptions.md)
 - [CompleteTurbiniaStats](docs/CompleteTurbiniaStats.md)
 - [HTTPValidationError](docs/HTTPValidationError.md)
 - [LocationInner](docs/LocationInner.md)
 - [Request](docs/Request.md)
 - [ValidationError](docs/ValidationError.md)


<a id="documentation-for-authorization"></a>
## Documentation For Authorization


Authentication schemes defined for the API:
<a id="oAuth2"></a>
### oAuth2

- **Type**: OAuth
- **Flow**: accessCode
- **Authorization URL**: https://accounts.google.com/o/oauth2/v2/auth
- **Scopes**: N/A


## Author



