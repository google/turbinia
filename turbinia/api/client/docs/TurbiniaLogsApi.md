# turbinia_api_lib.TurbiniaLogsApi

All URIs are relative to *http://localhost*

Method | HTTP request | Description
------------- | ------------- | -------------
[**get_logs**](TurbiniaLogsApi.md#get_logs) | **GET** /api/logs/{query} | Get Logs


# **get_logs**
> object get_logs(query)

Get Logs

Retrieve log data.

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
    api_instance = turbinia_api_lib.TurbiniaLogsApi(api_client)
    query = 'query_example' # str | 

    try:
        # Get Logs
        api_response = api_instance.get_logs(query)
        print("The response of TurbiniaLogsApi->get_logs:\n")
        pprint(api_response)
    except Exception as e:
        print("Exception when calling TurbiniaLogsApi->get_logs: %s\n" % e)
```



### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **query** | **str**|  | 

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

