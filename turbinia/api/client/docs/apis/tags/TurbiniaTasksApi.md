<a name="__pageTop"></a>
# turbinia_api_lib.apis.tags.turbinia_tasks_api.TurbiniaTasksApi

All URIs are relative to *http://localhost*

Method | HTTP request | Description
------------- | ------------- | -------------
[**get_task_statistics**](#get_task_statistics) | **get** /api/task/statistics | Get Task Statistics
[**get_task_status**](#get_task_status) | **get** /api/task/{task_id} | Get Task Status
[**get_workers_status**](#get_workers_status) | **get** /api/task/workers | Get Workers Status

# **get_task_statistics**
<a name="get_task_statistics"></a>
> CompleteTurbiniaStats get_task_statistics()

Get Task Statistics

Retrieves  statistics for Turbinia execution.  Args:   days (int): The number of days we want history for.   task_id (string): The Id of the task.   request_id (string): The Id of the request we want tasks for.   user (string): The user of the request we want tasks for.  Returns:   statistics (str): JSON-formatted task statistics report.

### Example

* OAuth Authentication (oAuth2):
```python
import turbinia_api_lib
from turbinia_api_lib.apis.tags import turbinia_tasks_api
from turbinia_api_lib.model.complete_turbinia_stats import CompleteTurbiniaStats
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
    host = "http://localhost",
    access_token = 'YOUR_ACCESS_TOKEN'
)
# Enter a context with an instance of the API client
with turbinia_api_lib.ApiClient(configuration) as api_client:
    # Create an instance of the API class
    api_instance = turbinia_tasks_api.TurbiniaTasksApi(api_client)

    # example passing only optional values
    query_params = {
        'days': 1,
        'task_id': "task_id_example",
        'request_id': "request_id_example",
        'user': "user_example",
    }
    try:
        # Get Task Statistics
        api_response = api_instance.get_task_statistics(
            query_params=query_params,
        )
        pprint(api_response)
    except turbinia_api_lib.ApiException as e:
        print("Exception when calling TurbiniaTasksApi->get_task_statistics: %s\n" % e)
```
### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
query_params | RequestQueryParams | |
accept_content_types | typing.Tuple[str] | default is ('application/json', ) | Tells the server the content type(s) that are accepted by the client
stream | bool | default is False | if True then the response.content will be streamed and loaded from a file like object. When downloading a file, set this to True to force the code to deserialize the content to a FileSchema file
timeout | typing.Optional[typing.Union[int, typing.Tuple]] | default is None | the timeout used by the rest client
skip_deserialization | bool | default is False | when True, headers and body will be unset and an instance of api_client.ApiResponseWithoutDeserialization will be returned

### query_params
#### RequestQueryParams

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
days | DaysSchema | | optional
task_id | TaskIdSchema | | optional
request_id | RequestIdSchema | | optional
user | UserSchema | | optional


# DaysSchema

## Model Type Info
Input Type | Accessed Type | Description | Notes
------------ | ------------- | ------------- | -------------
decimal.Decimal, int,  | decimal.Decimal,  |  | 

# TaskIdSchema

## Model Type Info
Input Type | Accessed Type | Description | Notes
------------ | ------------- | ------------- | -------------
str,  | str,  |  | 

# RequestIdSchema

## Model Type Info
Input Type | Accessed Type | Description | Notes
------------ | ------------- | ------------- | -------------
str,  | str,  |  | 

# UserSchema

## Model Type Info
Input Type | Accessed Type | Description | Notes
------------ | ------------- | ------------- | -------------
str,  | str,  |  | 

### Return Types, Responses

Code | Class | Description
------------- | ------------- | -------------
n/a | api_client.ApiResponseWithoutDeserialization | When skip_deserialization is True this response is returned
200 | [ApiResponseFor200](#get_task_statistics.ApiResponseFor200) | Successful Response
422 | [ApiResponseFor422](#get_task_statistics.ApiResponseFor422) | Validation Error

#### get_task_statistics.ApiResponseFor200
Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
response | urllib3.HTTPResponse | Raw response |
body | typing.Union[SchemaFor200ResponseBodyApplicationJson, ] |  |
headers | Unset | headers were not defined |

# SchemaFor200ResponseBodyApplicationJson
Type | Description  | Notes
------------- | ------------- | -------------
[**CompleteTurbiniaStats**](../../models/CompleteTurbiniaStats.md) |  | 


#### get_task_statistics.ApiResponseFor422
Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
response | urllib3.HTTPResponse | Raw response |
body | typing.Union[SchemaFor422ResponseBodyApplicationJson, ] |  |
headers | Unset | headers were not defined |

# SchemaFor422ResponseBodyApplicationJson
Type | Description  | Notes
------------- | ------------- | -------------
[**HTTPValidationError**](../../models/HTTPValidationError.md) |  | 


### Authorization

[oAuth2](../../../README.md#oAuth2)

[[Back to top]](#__pageTop) [[Back to API list]](../../../README.md#documentation-for-api-endpoints) [[Back to Model list]](../../../README.md#documentation-for-models) [[Back to README]](../../../README.md)

# **get_task_status**
<a name="get_task_status"></a>
> bool, date, datetime, dict, float, int, list, str, none_type get_task_status(task_id)

Get Task Status

Retrieve task information.

### Example

* OAuth Authentication (oAuth2):
```python
import turbinia_api_lib
from turbinia_api_lib.apis.tags import turbinia_tasks_api
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
    host = "http://localhost",
    access_token = 'YOUR_ACCESS_TOKEN'
)
# Enter a context with an instance of the API client
with turbinia_api_lib.ApiClient(configuration) as api_client:
    # Create an instance of the API class
    api_instance = turbinia_tasks_api.TurbiniaTasksApi(api_client)

    # example passing only required values which don't have defaults set
    path_params = {
        'task_id': "task_id_example",
    }
    try:
        # Get Task Status
        api_response = api_instance.get_task_status(
            path_params=path_params,
        )
        pprint(api_response)
    except turbinia_api_lib.ApiException as e:
        print("Exception when calling TurbiniaTasksApi->get_task_status: %s\n" % e)
```
### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
path_params | RequestPathParams | |
accept_content_types | typing.Tuple[str] | default is ('application/json', ) | Tells the server the content type(s) that are accepted by the client
stream | bool | default is False | if True then the response.content will be streamed and loaded from a file like object. When downloading a file, set this to True to force the code to deserialize the content to a FileSchema file
timeout | typing.Optional[typing.Union[int, typing.Tuple]] | default is None | the timeout used by the rest client
skip_deserialization | bool | default is False | when True, headers and body will be unset and an instance of api_client.ApiResponseWithoutDeserialization will be returned

### path_params
#### RequestPathParams

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
task_id | TaskIdSchema | | 

# TaskIdSchema

## Model Type Info
Input Type | Accessed Type | Description | Notes
------------ | ------------- | ------------- | -------------
str,  | str,  |  | 

### Return Types, Responses

Code | Class | Description
------------- | ------------- | -------------
n/a | api_client.ApiResponseWithoutDeserialization | When skip_deserialization is True this response is returned
200 | [ApiResponseFor200](#get_task_status.ApiResponseFor200) | Successful Response
422 | [ApiResponseFor422](#get_task_status.ApiResponseFor422) | Validation Error

#### get_task_status.ApiResponseFor200
Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
response | urllib3.HTTPResponse | Raw response |
body | typing.Union[SchemaFor200ResponseBodyApplicationJson, ] |  |
headers | Unset | headers were not defined |

# SchemaFor200ResponseBodyApplicationJson

## Model Type Info
Input Type | Accessed Type | Description | Notes
------------ | ------------- | ------------- | -------------
dict, frozendict.frozendict, str, date, datetime, uuid.UUID, int, float, decimal.Decimal, bool, None, list, tuple, bytes, io.FileIO, io.BufferedReader,  | frozendict.frozendict, str, decimal.Decimal, BoolClass, NoneClass, tuple, bytes, FileIO |  | 

#### get_task_status.ApiResponseFor422
Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
response | urllib3.HTTPResponse | Raw response |
body | typing.Union[SchemaFor422ResponseBodyApplicationJson, ] |  |
headers | Unset | headers were not defined |

# SchemaFor422ResponseBodyApplicationJson
Type | Description  | Notes
------------- | ------------- | -------------
[**HTTPValidationError**](../../models/HTTPValidationError.md) |  | 


### Authorization

[oAuth2](../../../README.md#oAuth2)

[[Back to top]](#__pageTop) [[Back to API list]](../../../README.md#documentation-for-api-endpoints) [[Back to Model list]](../../../README.md#documentation-for-models) [[Back to README]](../../../README.md)

# **get_workers_status**
<a name="get_workers_status"></a>
> bool, date, datetime, dict, float, int, list, str, none_type get_workers_status()

Get Workers Status

Retrieves the workers status.  Args:   days (int): The UUID of the evidence.   all_fields (bool): Returns all status fields if set to true.  Returns:   workers_status (str): JSON-formatted workers status.  Raises:   HTTPException: if no worker is found.

### Example

* OAuth Authentication (oAuth2):
```python
import turbinia_api_lib
from turbinia_api_lib.apis.tags import turbinia_tasks_api
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
    host = "http://localhost",
    access_token = 'YOUR_ACCESS_TOKEN'
)
# Enter a context with an instance of the API client
with turbinia_api_lib.ApiClient(configuration) as api_client:
    # Create an instance of the API class
    api_instance = turbinia_tasks_api.TurbiniaTasksApi(api_client)

    # example passing only optional values
    query_params = {
        'days': 7,
        'all_fields': False,
    }
    try:
        # Get Workers Status
        api_response = api_instance.get_workers_status(
            query_params=query_params,
        )
        pprint(api_response)
    except turbinia_api_lib.ApiException as e:
        print("Exception when calling TurbiniaTasksApi->get_workers_status: %s\n" % e)
```
### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
query_params | RequestQueryParams | |
accept_content_types | typing.Tuple[str] | default is ('application/json', ) | Tells the server the content type(s) that are accepted by the client
stream | bool | default is False | if True then the response.content will be streamed and loaded from a file like object. When downloading a file, set this to True to force the code to deserialize the content to a FileSchema file
timeout | typing.Optional[typing.Union[int, typing.Tuple]] | default is None | the timeout used by the rest client
skip_deserialization | bool | default is False | when True, headers and body will be unset and an instance of api_client.ApiResponseWithoutDeserialization will be returned

### query_params
#### RequestQueryParams

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
days | DaysSchema | | optional
all_fields | AllFieldsSchema | | optional


# DaysSchema

## Model Type Info
Input Type | Accessed Type | Description | Notes
------------ | ------------- | ------------- | -------------
decimal.Decimal, int,  | decimal.Decimal,  |  | if omitted the server will use the default value of 7

# AllFieldsSchema

## Model Type Info
Input Type | Accessed Type | Description | Notes
------------ | ------------- | ------------- | -------------
bool,  | BoolClass,  |  | if omitted the server will use the default value of False

### Return Types, Responses

Code | Class | Description
------------- | ------------- | -------------
n/a | api_client.ApiResponseWithoutDeserialization | When skip_deserialization is True this response is returned
200 | [ApiResponseFor200](#get_workers_status.ApiResponseFor200) | Successful Response
422 | [ApiResponseFor422](#get_workers_status.ApiResponseFor422) | Validation Error

#### get_workers_status.ApiResponseFor200
Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
response | urllib3.HTTPResponse | Raw response |
body | typing.Union[SchemaFor200ResponseBodyApplicationJson, ] |  |
headers | Unset | headers were not defined |

# SchemaFor200ResponseBodyApplicationJson

## Model Type Info
Input Type | Accessed Type | Description | Notes
------------ | ------------- | ------------- | -------------
dict, frozendict.frozendict, str, date, datetime, uuid.UUID, int, float, decimal.Decimal, bool, None, list, tuple, bytes, io.FileIO, io.BufferedReader,  | frozendict.frozendict, str, decimal.Decimal, BoolClass, NoneClass, tuple, bytes, FileIO |  | 

#### get_workers_status.ApiResponseFor422
Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
response | urllib3.HTTPResponse | Raw response |
body | typing.Union[SchemaFor422ResponseBodyApplicationJson, ] |  |
headers | Unset | headers were not defined |

# SchemaFor422ResponseBodyApplicationJson
Type | Description  | Notes
------------- | ------------- | -------------
[**HTTPValidationError**](../../models/HTTPValidationError.md) |  | 


### Authorization

[oAuth2](../../../README.md#oAuth2)

[[Back to top]](#__pageTop) [[Back to API list]](../../../README.md#documentation-for-api-endpoints) [[Back to Model list]](../../../README.md#documentation-for-models) [[Back to README]](../../../README.md)

