# turbinia_api_client.TurbiniaTasksApi

All URIs are relative to *http://localhost*

Method | HTTP request | Description
------------- | ------------- | -------------
[**get_task_status**](TurbiniaTasksApi.md#get_task_status) | **GET** /task/{task_id} | Get Task Status


# **get_task_status**
> bool, date, datetime, dict, float, int, list, str, none_type get_task_status(task_id)

Get Task Status

Retrieve task information.

### Example


```python
import time
import turbinia_api_client
from turbinia_api_client.api import turbinia_tasks_api
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
    api_instance = turbinia_tasks_api.TurbiniaTasksApi(api_client)
    task_id = "task_id_example" # str | 

    # example passing only required values which don't have defaults set
    try:
        # Get Task Status
        api_response = api_instance.get_task_status(task_id)
        pprint(api_response)
    except turbinia_api_client.ApiException as e:
        print("Exception when calling TurbiniaTasksApi->get_task_status: %s\n" % e)
```


### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **task_id** | **str**|  |

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

