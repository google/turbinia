# turbinia_api_lib.TurbiniaRequestsApi

All URIs are relative to *http://localhost*

Method | HTTP request | Description
------------- | ------------- | -------------
[**create_request**](TurbiniaRequestsApi.md#create_request) | **POST** /api/request/ | Create Request
[**get_request_status**](TurbiniaRequestsApi.md#get_request_status) | **GET** /api/request/{request_id} | Get Request Status
[**get_requests_summary**](TurbiniaRequestsApi.md#get_requests_summary) | **GET** /api/request/summary | Get Requests Summary


# **create_request**
> bool, date, datetime, dict, float, int, list, str, none_type create_request(request)

Create Request

Create a new Turbinia request.  Args:   request (turbinia.api.schema.request): JSON object from the HTTP POST data       matching the schema defined for a Turbinia Request. The schema is used       by pydantic for field validation.  Raises:   ValidationError: if the Request object contains invalid data.   HTTPException: If pre-conditions are not met.

### Example

* OAuth Authentication (oAuth2):

```python
import time
import turbinia_api_lib
from turbinia_api_lib.api import turbinia_requests_api
from turbinia_api_lib.model.http_validation_error import HTTPValidationError
from turbinia_api_lib.model.request import Request
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

# Configure OAuth2 access token for authorization: oAuth2
configuration = turbinia_api_lib.Configuration(
    host = "http://localhost"
)
configuration.access_token = 'YOUR_ACCESS_TOKEN'

# Enter a context with an instance of the API client
with turbinia_api_lib.ApiClient(configuration) as api_client:
    # Create an instance of the API class
    api_instance = turbinia_requests_api.TurbiniaRequestsApi(api_client)
    request = Request(
        description="Turbinia request object",
        evidence={},
        request_options=BaseRequestOptions(
            filter_patterns=[
                "filter_patterns_example",
            ],
            group_id="group_id_example",
            jobs_allowlist=[
                "jobs_allowlist_example",
            ],
            jobs_denylist=[
                "jobs_denylist_example",
            ],
            reason="reason_example",
            recipe_data="recipe_data_example",
            recipe_name="recipe_name_example",
            request_id="request_id_example",
            requester="requester_example",
            sketch_id=1,
            yara_rules="yara_rules_example",
        ),
    ) # Request | 

    # example passing only required values which don't have defaults set
    try:
        # Create Request
        api_response = api_instance.create_request(request)
        pprint(api_response)
    except turbinia_api_lib.ApiException as e:
        print("Exception when calling TurbiniaRequestsApi->create_request: %s\n" % e)
```


### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **request** | [**Request**](Request.md)|  |

### Return type

**bool, date, datetime, dict, float, int, list, str, none_type**

### Authorization

[oAuth2](../README.md#oAuth2)

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
> bool, date, datetime, dict, float, int, list, str, none_type get_request_status(request_id)

Get Request Status

Retrieves status for a Turbinia Request.  Args:   request_id (str): A Turbinia request identifier.  Raises:   HTTPException: if another exception is caught.

### Example

* OAuth Authentication (oAuth2):

```python
import time
import turbinia_api_lib
from turbinia_api_lib.api import turbinia_requests_api
from turbinia_api_lib.model.http_validation_error import HTTPValidationError
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

# Configure OAuth2 access token for authorization: oAuth2
configuration = turbinia_api_lib.Configuration(
    host = "http://localhost"
)
configuration.access_token = 'YOUR_ACCESS_TOKEN'

# Enter a context with an instance of the API client
with turbinia_api_lib.ApiClient(configuration) as api_client:
    # Create an instance of the API class
    api_instance = turbinia_requests_api.TurbiniaRequestsApi(api_client)
    request_id = "request_id_example" # str | 

    # example passing only required values which don't have defaults set
    try:
        # Get Request Status
        api_response = api_instance.get_request_status(request_id)
        pprint(api_response)
    except turbinia_api_lib.ApiException as e:
        print("Exception when calling TurbiniaRequestsApi->get_request_status: %s\n" % e)
```


### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **request_id** | **str**|  |

### Return type

**bool, date, datetime, dict, float, int, list, str, none_type**

### Authorization

[oAuth2](../README.md#oAuth2)

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
> bool, date, datetime, dict, float, int, list, str, none_type get_requests_summary()

Get Requests Summary

Retrieves a summary of all Turbinia requests.  The response is validated against the RequestSummary model.  Raises:   HTTPException: if another exception is caught.

### Example

* OAuth Authentication (oAuth2):

```python
import time
import turbinia_api_lib
from turbinia_api_lib.api import turbinia_requests_api
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

# Configure OAuth2 access token for authorization: oAuth2
configuration = turbinia_api_lib.Configuration(
    host = "http://localhost"
)
configuration.access_token = 'YOUR_ACCESS_TOKEN'

# Enter a context with an instance of the API client
with turbinia_api_lib.ApiClient(configuration) as api_client:
    # Create an instance of the API class
    api_instance = turbinia_requests_api.TurbiniaRequestsApi(api_client)

    # example, this endpoint has no required or optional parameters
    try:
        # Get Requests Summary
        api_response = api_instance.get_requests_summary()
        pprint(api_response)
    except turbinia_api_lib.ApiException as e:
        print("Exception when calling TurbiniaRequestsApi->get_requests_summary: %s\n" % e)
```


### Parameters
This endpoint does not need any parameter.

### Return type

**bool, date, datetime, dict, float, int, list, str, none_type**

### Authorization

[oAuth2](../README.md#oAuth2)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json


### HTTP response details

| Status code | Description | Response headers |
|-------------|-------------|------------------|
**200** | Successful Response |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

