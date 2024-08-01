# turbinia_api_lib.TurbiniaRequestsApi

All URIs are relative to *http://localhost*

Method | HTTP request | Description
------------- | ------------- | -------------
[**create_request**](TurbiniaRequestsApi.md#create_request) | **POST** /api/request/ | Create Request
[**get_request_report**](TurbiniaRequestsApi.md#get_request_report) | **GET** /api/request/report/{request_id} | Get Request Markdown Report
[**get_request_status**](TurbiniaRequestsApi.md#get_request_status) | **GET** /api/request/{request_id} | Get Request Status
[**get_requests_summary**](TurbiniaRequestsApi.md#get_requests_summary) | **GET** /api/request/summary | Get Requests Summary


# **create_request**
> object create_request(request)

Create Request

Create a new Turbinia request.  Args:   request (Request): FastAPI request object.   req (turbinia.api.schema.request): JSON object from the HTTP POST data       matching the schema defined for a Turbinia Request. The schema is used       by pydantic for field validation.  Raises:   ValidationError: if the Request object contains invalid data.   HTTPException: If pre-conditions are not met.

### Example

* OAuth Authentication (oAuth2):
```python
import time
import os
import turbinia_api_lib
from turbinia_api_lib.models.request import Request
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
    api_instance = turbinia_api_lib.TurbiniaRequestsApi(api_client)
    request = turbinia_api_lib.Request() # Request | 

    try:
        # Create Request
        api_response = api_instance.create_request(request)
        print("The response of TurbiniaRequestsApi->create_request:\n")
        pprint(api_response)
    except Exception as e:
        print("Exception when calling TurbiniaRequestsApi->create_request: %s\n" % e)
```



### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **request** | [**Request**](Request.md)|  | 

### Return type

**object**

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

# **get_request_report**
> str get_request_report(request_id)

Get Request Markdown Report

Retrieves the markdown report for a Turbinia Request.  Args:   request (Request): FastAPI request object.   request_id (str): A Turbinia request identifier.  Raises:   HTTPException: if another exception is caught.

### Example

* OAuth Authentication (oAuth2):
```python
import time
import os
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
    api_instance = turbinia_api_lib.TurbiniaRequestsApi(api_client)
    request_id = 'request_id_example' # str | 

    try:
        # Get Request Markdown Report
        api_response = api_instance.get_request_report(request_id)
        print("The response of TurbiniaRequestsApi->get_request_report:\n")
        pprint(api_response)
    except Exception as e:
        print("Exception when calling TurbiniaRequestsApi->get_request_report: %s\n" % e)
```



### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **request_id** | **str**|  | 

### Return type

**str**

### Authorization

[oAuth2](../README.md#oAuth2)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/text

### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
**200** | Successful Response |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **get_request_status**
> object get_request_status(request_id)

Get Request Status

Retrieves status for a Turbinia Request.  Args:   request (Request): FastAPI request object.   request_id (str): A Turbinia request identifier.  Raises:   HTTPException: if another exception is caught.

### Example

* OAuth Authentication (oAuth2):
```python
import time
import os
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
    api_instance = turbinia_api_lib.TurbiniaRequestsApi(api_client)
    request_id = 'request_id_example' # str | 

    try:
        # Get Request Status
        api_response = api_instance.get_request_status(request_id)
        print("The response of TurbiniaRequestsApi->get_request_status:\n")
        pprint(api_response)
    except Exception as e:
        print("Exception when calling TurbiniaRequestsApi->get_request_status: %s\n" % e)
```



### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **request_id** | **str**|  | 

### Return type

**object**

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
> object get_requests_summary()

Get Requests Summary

Retrieves a summary of all Turbinia requests.  The response is validated against the RequestSummary model.  Raises:   HTTPException: if another exception is caught.

### Example

* OAuth Authentication (oAuth2):
```python
import time
import os
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
    api_instance = turbinia_api_lib.TurbiniaRequestsApi(api_client)

    try:
        # Get Requests Summary
        api_response = api_instance.get_requests_summary()
        print("The response of TurbiniaRequestsApi->get_requests_summary:\n")
        pprint(api_response)
    except Exception as e:
        print("Exception when calling TurbiniaRequestsApi->get_requests_summary: %s\n" % e)
```



### Parameters
This endpoint does not need any parameter.

### Return type

**object**

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

