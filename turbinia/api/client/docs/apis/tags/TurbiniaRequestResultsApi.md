<a name="__pageTop"></a>
# turbinia_api_lib.apis.tags.turbinia_request_results_api.TurbiniaRequestResultsApi

All URIs are relative to *http://localhost*

Method | HTTP request | Description
------------- | ------------- | -------------
[**get_request_output**](#get_request_output) | **get** /api/result/request/{request_id} | Get Request Output
[**get_task_output**](#get_task_output) | **get** /api/result/task/{task_id} | Get Task Output

# **get_request_output**
<a name="get_request_output"></a>
> file_type get_request_output(request_id)

Get Request Output

Retrieve request output.

### Example

* OAuth Authentication (oAuth2):
```python
import turbinia_api_lib
from turbinia_api_lib.apis.tags import turbinia_request_results_api
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
    api_instance = turbinia_request_results_api.TurbiniaRequestResultsApi(api_client)

    # example passing only required values which don't have defaults set
    path_params = {
        'request_id': "request_id_example",
    }
    try:
        # Get Request Output
        api_response = api_instance.get_request_output(
            path_params=path_params,
        )
        pprint(api_response)
    except turbinia_api_lib.ApiException as e:
        print("Exception when calling TurbiniaRequestResultsApi->get_request_output: %s\n" % e)
```
### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
path_params | RequestPathParams | |
accept_content_types | typing.Tuple[str] | default is ('application/octet-stream', 'application/json', ) | Tells the server the content type(s) that are accepted by the client
stream | bool | default is False | if True then the response.content will be streamed and loaded from a file like object. When downloading a file, set this to True to force the code to deserialize the content to a FileSchema file
timeout | typing.Optional[typing.Union[int, typing.Tuple]] | default is None | the timeout used by the rest client
skip_deserialization | bool | default is False | when True, headers and body will be unset and an instance of api_client.ApiResponseWithoutDeserialization will be returned

### path_params
#### RequestPathParams

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
request_id | RequestIdSchema | | 

# RequestIdSchema

## Model Type Info
Input Type | Accessed Type | Description | Notes
------------ | ------------- | ------------- | -------------
str,  | str,  |  | 

### Return Types, Responses

Code | Class | Description
------------- | ------------- | -------------
n/a | api_client.ApiResponseWithoutDeserialization | When skip_deserialization is True this response is returned
200 | [ApiResponseFor200](#get_request_output.ApiResponseFor200) | Successful Response
422 | [ApiResponseFor422](#get_request_output.ApiResponseFor422) | Validation Error

#### get_request_output.ApiResponseFor200
Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
response | urllib3.HTTPResponse | Raw response |
body | typing.Union[SchemaFor200ResponseBodyApplicationOctetStream, ] |  |
headers | Unset | headers were not defined |

# SchemaFor200ResponseBodyApplicationOctetStream

## Model Type Info
Input Type | Accessed Type | Description | Notes
------------ | ------------- | ------------- | -------------
bytes, io.FileIO, io.BufferedReader,  | bytes, FileIO,  |  | 

#### get_request_output.ApiResponseFor422
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

# **get_task_output**
<a name="get_task_output"></a>
> file_type get_task_output(task_id)

Get Task Output

Retrieves a task's output files.

### Example

* OAuth Authentication (oAuth2):
```python
import turbinia_api_lib
from turbinia_api_lib.apis.tags import turbinia_request_results_api
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
    api_instance = turbinia_request_results_api.TurbiniaRequestResultsApi(api_client)

    # example passing only required values which don't have defaults set
    path_params = {
        'task_id': "task_id_example",
    }
    try:
        # Get Task Output
        api_response = api_instance.get_task_output(
            path_params=path_params,
        )
        pprint(api_response)
    except turbinia_api_lib.ApiException as e:
        print("Exception when calling TurbiniaRequestResultsApi->get_task_output: %s\n" % e)
```
### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
path_params | RequestPathParams | |
accept_content_types | typing.Tuple[str] | default is ('application/octet-stream', 'application/json', ) | Tells the server the content type(s) that are accepted by the client
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
200 | [ApiResponseFor200](#get_task_output.ApiResponseFor200) | Successful Response
422 | [ApiResponseFor422](#get_task_output.ApiResponseFor422) | Validation Error

#### get_task_output.ApiResponseFor200
Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
response | urllib3.HTTPResponse | Raw response |
body | typing.Union[SchemaFor200ResponseBodyApplicationOctetStream, ] |  |
headers | Unset | headers were not defined |

# SchemaFor200ResponseBodyApplicationOctetStream

## Model Type Info
Input Type | Accessed Type | Description | Notes
------------ | ------------- | ------------- | -------------
bytes, io.FileIO, io.BufferedReader,  | bytes, FileIO,  |  | 

#### get_task_output.ApiResponseFor422
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

