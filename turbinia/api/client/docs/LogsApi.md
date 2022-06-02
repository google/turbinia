# turbinia_api_client.LogsApi

All URIs are relative to *http://localhost*

Method | HTTP request | Description
------------- | ------------- | -------------
[**get_logs**](LogsApi.md#get_logs) | **GET** /logs/{query} | Get Logs


# **get_logs**
> bool, date, datetime, dict, float, int, list, str, none_type get_logs(query)

Get Logs

Retrieve log data.

### Example


```python
import time
import turbinia_api_client
from turbinia_api_client.api import logs_api
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
    api_instance = logs_api.LogsApi(api_client)
    query = "query_example" # str | 

    # example passing only required values which don't have defaults set
    try:
        # Get Logs
        api_response = api_instance.get_logs(query)
        pprint(api_response)
    except turbinia_api_client.ApiException as e:
        print("Exception when calling LogsApi->get_logs: %s\n" % e)
```


### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **query** | **str**|  |

### Return type

**bool, date, datetime, dict, float, int, list, str, none_type**

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

