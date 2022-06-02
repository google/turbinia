# turbinia_api_client.TurbiniaRequestResultsApi

All URIs are relative to *http://localhost*

Method | HTTP request | Description
------------- | ------------- | -------------
[**get_request_output**](TurbiniaRequestResultsApi.md#get_request_output) | **GET** /result/request/{request_id} | Get Request Output
[**get_task_output**](TurbiniaRequestResultsApi.md#get_task_output) | **GET** /result/task/{task_id} | Get Task Output


# **get_request_output**
> bool, date, datetime, dict, float, int, list, str, none_type get_request_output(request_id)

Get Request Output

Retrieve request status output.

### Example


```python
import time
import turbinia_api_client
from turbinia_api_client.api import turbinia_request_results_api
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
    api_instance = turbinia_request_results_api.TurbiniaRequestResultsApi(api_client)
    request_id = "request_id_example" # str | 

    # example passing only required values which don't have defaults set
    try:
        # Get Request Output
        api_response = api_instance.get_request_output(request_id)
        pprint(api_response)
    except turbinia_api_client.ApiException as e:
        print("Exception when calling TurbiniaRequestResultsApi->get_request_output: %s\n" % e)
```


### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **request_id** | **str**|  |

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

# **get_task_output**
> bool, date, datetime, dict, float, int, list, str, none_type get_task_output(task_id)

Get Task Output

Retrieves a task's output files.

### Example


```python
import time
import turbinia_api_client
from turbinia_api_client.api import turbinia_request_results_api
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
    api_instance = turbinia_request_results_api.TurbiniaRequestResultsApi(api_client)
    task_id = "task_id_example" # str | 

    # example passing only required values which don't have defaults set
    try:
        # Get Task Output
        api_response = api_instance.get_task_output(task_id)
        pprint(api_response)
    except turbinia_api_client.ApiException as e:
        print("Exception when calling TurbiniaRequestResultsApi->get_task_output: %s\n" % e)
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

