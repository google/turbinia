# turbinia_api_client.TurbiniaRequestsApi

All URIs are relative to *http://localhost*

Method | HTTP request | Description
------------- | ------------- | -------------
[**create_request**](TurbiniaRequestsApi.md#create_request) | **POST** /request/ | Create Request
[**get_request_status**](TurbiniaRequestsApi.md#get_request_status) | **GET** /request/{request_id} | Get Request Status
[**get_requests_summary**](TurbiniaRequestsApi.md#get_requests_summary) | **GET** /request/summary | Get Requests Summary


# **create_request**
> bool, date, datetime, dict, float, int, list, str, none_type create_request(request)

Create Request

Create a new Turbinia request.  Args:   request (turbinia.api.schema.request): JSON object from the HTTP POST data       matching the schema defined for a Turbinia Request. The schema is used       by pydantic for field validation.  Raises:   ValidationError: if the Request object contains invalid data.

### Example


```python
import time
import turbinia_api_client
from turbinia_api_client.api import turbinia_requests_api
from turbinia_api_client.model.request import Request
from turbinia_api_client.model.http_validation_error import HTTPValidationError
from pprint import pprint
# Defining the host is optional and defaults to http://localhost
# See configuration.py for a list of all supported configuration parameters.
configuration = turbinia_api_client.Configuration(
    host = "http://localhost"
)


# Enter a context with an instance of the API client
with turbinia_api_client.ApiClient() as api_client:
    # Create an instance of the API class
    api_instance = turbinia_requests_api.TurbiniaRequestsApi(api_client)
    request = Request(
        description="Turbinia request object",
        evidence_options=BaseEvidenceOptions(
            filter_patterns=[
                "filter_patterns_example",
            ],
            jobs_allowlist=[
                "jobs_allowlist_example",
            ],
            jobs_denylist=[
                "jobs_denylist_example",
            ],
            name="name_example",
            sketch_id=1,
            source_path="source_path_example",
            turbinia_recipe="turbinia_recipe_example",
            yara_rules="yara_rules_example",
        ),
        evidence_type=EvidenceTypesEnum("compresseddirectory"),
        group_id="group_id_example",
        reason="reason_example",
        request_id="request_id_example",
        requester="requester_example",
        sketch_id="sketch_id_example",
    ) # Request | 

    # example passing only required values which don't have defaults set
    try:
        # Create Request
        api_response = api_instance.create_request(request)
        pprint(api_response)
    except turbinia_api_client.ApiException as e:
        print("Exception when calling TurbiniaRequestsApi->create_request: %s\n" % e)
```


### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **request** | [**Request**](Request.md)|  |

### Return type

**bool, date, datetime, dict, float, int, list, str, none_type**

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json


### HTTP response details

| Status code | Description | Response headers |
|-------------|-------------|------------------|
**200** | Successful Response |  -  |
**422** | Validation Error |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **get_request_status**
> RequestStatus get_request_status(request_id)

Get Request Status

Retrieves status for a Turbinia Request.  Args:   request_id (str): A Turbinia request identifier.  Raises:   HTTPException: if another exception is caught.

### Example


```python
import time
import turbinia_api_client
from turbinia_api_client.api import turbinia_requests_api
from turbinia_api_client.model.request_status import RequestStatus
from turbinia_api_client.model.http_validation_error import HTTPValidationError
from pprint import pprint
# Defining the host is optional and defaults to http://localhost
# See configuration.py for a list of all supported configuration parameters.
configuration = turbinia_api_client.Configuration(
    host = "http://localhost"
)


# Enter a context with an instance of the API client
with turbinia_api_client.ApiClient() as api_client:
    # Create an instance of the API class
    api_instance = turbinia_requests_api.TurbiniaRequestsApi(api_client)
    request_id = "request_id_example" # str | 

    # example passing only required values which don't have defaults set
    try:
        # Get Request Status
        api_response = api_instance.get_request_status(request_id)
        pprint(api_response)
    except turbinia_api_client.ApiException as e:
        print("Exception when calling TurbiniaRequestsApi->get_request_status: %s\n" % e)
```


### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **request_id** | **str**|  |

### Return type

[**RequestStatus**](RequestStatus.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json


### HTTP response details

| Status code | Description | Response headers |
|-------------|-------------|------------------|
**200** | Successful Response |  -  |
**422** | Validation Error |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **get_requests_summary**
> RequestsSummary get_requests_summary()

Get Requests Summary

Retrieves a summary of all Turbinia requests.  The response is validated against the RequestSummary model.  Raises:   HTTPException: if another exception is caught.

### Example


```python
import time
import turbinia_api_client
from turbinia_api_client.api import turbinia_requests_api
from turbinia_api_client.model.requests_summary import RequestsSummary
from pprint import pprint
# Defining the host is optional and defaults to http://localhost
# See configuration.py for a list of all supported configuration parameters.
configuration = turbinia_api_client.Configuration(
    host = "http://localhost"
)


# Enter a context with an instance of the API client
with turbinia_api_client.ApiClient() as api_client:
    # Create an instance of the API class
    api_instance = turbinia_requests_api.TurbiniaRequestsApi(api_client)

    # example, this endpoint has no required or optional parameters
    try:
        # Get Requests Summary
        api_response = api_instance.get_requests_summary()
        pprint(api_response)
    except turbinia_api_client.ApiException as e:
        print("Exception when calling TurbiniaRequestsApi->get_requests_summary: %s\n" % e)
```


### Parameters
This endpoint does not need any parameter.

### Return type

[**RequestsSummary**](RequestsSummary.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json


### HTTP response details

| Status code | Description | Response headers |
|-------------|-------------|------------------|
**200** | Successful Response |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

