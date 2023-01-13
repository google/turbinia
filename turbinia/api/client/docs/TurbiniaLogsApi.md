# turbinia_api_lib.TurbiniaLogsApi

All URIs are relative to *http://localhost*

Method | HTTP request | Description
------------- | ------------- | -------------
[**get_logs**](TurbiniaLogsApi.md#get_logs) | **GET** /api/logs/{query} | Get Logs


# **get_logs**
> bool, date, datetime, dict, float, int, list, str, none_type get_logs(query)

Get Logs

Retrieve log data.

### Example

* OAuth Authentication (oAuth2):

```python
import time
import turbinia_api_lib
from turbinia_api_lib.api import turbinia_logs_api
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
    api_instance = turbinia_logs_api.TurbiniaLogsApi(api_client)
    query = "query_example" # str | 

    # example passing only required values which don't have defaults set
    try:
        # Get Logs
        api_response = api_instance.get_logs(query)
        pprint(api_response)
    except turbinia_api_lib.ApiException as e:
        print("Exception when calling TurbiniaLogsApi->get_logs: %s\n" % e)
```


### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **query** | **str**|  |

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

