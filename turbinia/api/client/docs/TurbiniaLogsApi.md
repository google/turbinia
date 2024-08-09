# turbinia_api_lib.TurbiniaLogsApi

All URIs are relative to *http://localhost*

Method | HTTP request | Description
------------- | ------------- | -------------
[**get_api_server_logs**](TurbiniaLogsApi.md#get_api_server_logs) | **GET** /api/logs/api_server | Get Api Server Logs
[**get_server_logs**](TurbiniaLogsApi.md#get_server_logs) | **GET** /api/logs/server | Get Server Logs
[**get_turbinia_logs**](TurbiniaLogsApi.md#get_turbinia_logs) | **GET** /api/logs/{hostname} | Get Turbinia Logs


# **get_api_server_logs**
> str get_api_server_logs(num_lines=num_lines)

Get Api Server Logs

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
    num_lines = 500 # int |  (optional) (default to 500)

    try:
        # Get Api Server Logs
        api_response = api_instance.get_api_server_logs(num_lines=num_lines)
        print("The response of TurbiniaLogsApi->get_api_server_logs:\n")
        pprint(api_response)
    except Exception as e:
        print("Exception when calling TurbiniaLogsApi->get_api_server_logs: %s\n" % e)
```



### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **num_lines** | **int**|  | [optional] [default to 500]

### Return type

**str**

### Authorization

[oAuth2](../README.md#oAuth2)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/text, application/json

### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
**200** | Successful Response |  -  |
**422** | Validation Error |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **get_server_logs**
> str get_server_logs(num_lines=num_lines)

Get Server Logs

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
    num_lines = 500 # int |  (optional) (default to 500)

    try:
        # Get Server Logs
        api_response = api_instance.get_server_logs(num_lines=num_lines)
        print("The response of TurbiniaLogsApi->get_server_logs:\n")
        pprint(api_response)
    except Exception as e:
        print("Exception when calling TurbiniaLogsApi->get_server_logs: %s\n" % e)
```



### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **num_lines** | **int**|  | [optional] [default to 500]

### Return type

**str**

### Authorization

[oAuth2](../README.md#oAuth2)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/text, application/json

### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
**200** | Successful Response |  -  |
**422** | Validation Error |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **get_turbinia_logs**
> str get_turbinia_logs(hostname, num_lines=num_lines)

Get Turbinia Logs

Retrieve log data.  Turbinia currently stores logs on plaintext files. The log files are named <hostname>.log for each instance of a worker, server or API server.  In some deployments, the same file can contain all logs (e.g. running all services locally in the same container).

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
    hostname = 'hostname_example' # str | 
    num_lines = 500 # int |  (optional) (default to 500)

    try:
        # Get Turbinia Logs
        api_response = api_instance.get_turbinia_logs(hostname, num_lines=num_lines)
        print("The response of TurbiniaLogsApi->get_turbinia_logs:\n")
        pprint(api_response)
    except Exception as e:
        print("Exception when calling TurbiniaLogsApi->get_turbinia_logs: %s\n" % e)
```



### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **hostname** | **str**|  | 
 **num_lines** | **int**|  | [optional] [default to 500]

### Return type

**str**

### Authorization

[oAuth2](../README.md#oAuth2)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/text, application/json

### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
**200** | Successful Response |  -  |
**422** | Validation Error |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

