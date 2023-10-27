# turbinia_api_lib.TurbiniaTasksApi

All URIs are relative to *http://localhost*

Method | HTTP request | Description
------------- | ------------- | -------------
[**get_task_statistics**](TurbiniaTasksApi.md#get_task_statistics) | **GET** /api/task/statistics | Get Task Statistics
[**get_task_status**](TurbiniaTasksApi.md#get_task_status) | **GET** /api/task/{task_id} | Get Task Status
[**get_workers_status**](TurbiniaTasksApi.md#get_workers_status) | **GET** /api/task/workers | Get Workers Status


# **get_task_statistics**
> CompleteTurbiniaStats get_task_statistics(days=days, task_id=task_id, request_id=request_id, user=user)

Get Task Statistics

Retrieves  statistics for Turbinia execution.  Args:   days (int): The number of days we want history for.   task_id (string): The Id of the task.   request_id (string): The Id of the request we want tasks for.   user (string): The user of the request we want tasks for.  Returns:   statistics (str): JSON-formatted task statistics report.

### Example

* OAuth Authentication (oAuth2):
```python
import time
import os
import turbinia_api_lib
from turbinia_api_lib.models.complete_turbinia_stats import CompleteTurbiniaStats
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
    api_instance = turbinia_api_lib.TurbiniaTasksApi(api_client)
    days = 56 # int |  (optional)
    task_id = 'task_id_example' # str |  (optional)
    request_id = 'request_id_example' # str |  (optional)
    user = 'user_example' # str |  (optional)

    try:
        # Get Task Statistics
        api_response = api_instance.get_task_statistics(days=days, task_id=task_id, request_id=request_id, user=user)
        print("The response of TurbiniaTasksApi->get_task_statistics:\n")
        pprint(api_response)
    except Exception as e:
        print("Exception when calling TurbiniaTasksApi->get_task_statistics: %s\n" % e)
```



### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **days** | **int**|  | [optional] 
 **task_id** | **str**|  | [optional] 
 **request_id** | **str**|  | [optional] 
 **user** | **str**|  | [optional] 

### Return type

[**CompleteTurbiniaStats**](CompleteTurbiniaStats.md)

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

# **get_task_status**
> object get_task_status(task_id)

Get Task Status

Retrieve task information.

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
    api_instance = turbinia_api_lib.TurbiniaTasksApi(api_client)
    task_id = 'task_id_example' # str | 

    try:
        # Get Task Status
        api_response = api_instance.get_task_status(task_id)
        print("The response of TurbiniaTasksApi->get_task_status:\n")
        pprint(api_response)
    except Exception as e:
        print("Exception when calling TurbiniaTasksApi->get_task_status: %s\n" % e)
```



### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **task_id** | **str**|  | 

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

# **get_workers_status**
> object get_workers_status(days=days, all_fields=all_fields)

Get Workers Status

Retrieves the workers status.  Args:   days (int): The UUID of the evidence.   all_fields (bool): Returns all status fields if set to true.  Returns:   workers_status (str): JSON-formatted workers status.  Raises:   HTTPException: if no worker is found.

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
    api_instance = turbinia_api_lib.TurbiniaTasksApi(api_client)
    days = 7 # int |  (optional) (default to 7)
    all_fields = False # bool |  (optional) (default to False)

    try:
        # Get Workers Status
        api_response = api_instance.get_workers_status(days=days, all_fields=all_fields)
        print("The response of TurbiniaTasksApi->get_workers_status:\n")
        pprint(api_response)
    except Exception as e:
        print("Exception when calling TurbiniaTasksApi->get_workers_status: %s\n" % e)
```



### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **days** | **int**|  | [optional] [default to 7]
 **all_fields** | **bool**|  | [optional] [default to False]

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

