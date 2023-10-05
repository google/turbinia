<a name="__pageTop"></a>
# turbinia_api_lib.apis.tags.turbinia_configuration_api.TurbiniaConfigurationApi

All URIs are relative to *http://localhost*

Method | HTTP request | Description
------------- | ------------- | -------------
[**get_request_options**](#get_request_options) | **get** /api/config/request_options | Get Request Options
[**read_config**](#read_config) | **get** /api/config/ | Read Config

# **get_request_options**
<a name="get_request_options"></a>
> bool, date, datetime, dict, float, int, list, str, none_type get_request_options()

Get Request Options

Returns a list BaseRequestOptions attributes.

### Example

* OAuth Authentication (oAuth2):
```python
import turbinia_api_lib
from turbinia_api_lib.apis.tags import turbinia_configuration_api
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
    api_instance = turbinia_configuration_api.TurbiniaConfigurationApi(api_client)

    # example, this endpoint has no required or optional parameters
    try:
        # Get Request Options
        api_response = api_instance.get_request_options()
        pprint(api_response)
    except turbinia_api_lib.ApiException as e:
        print("Exception when calling TurbiniaConfigurationApi->get_request_options: %s\n" % e)
```
### Parameters
This endpoint does not need any parameter.

### Return Types, Responses

Code | Class | Description
------------- | ------------- | -------------
n/a | api_client.ApiResponseWithoutDeserialization | When skip_deserialization is True this response is returned
200 | [ApiResponseFor200](#get_request_options.ApiResponseFor200) | Successful Response

#### get_request_options.ApiResponseFor200
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

### Authorization

[oAuth2](../../../README.md#oAuth2)

[[Back to top]](#__pageTop) [[Back to API list]](../../../README.md#documentation-for-api-endpoints) [[Back to Model list]](../../../README.md#documentation-for-models) [[Back to README]](../../../README.md)

# **read_config**
<a name="read_config"></a>
> bool, date, datetime, dict, float, int, list, str, none_type read_config()

Read Config

Retrieve turbinia config.

### Example

* OAuth Authentication (oAuth2):
```python
import turbinia_api_lib
from turbinia_api_lib.apis.tags import turbinia_configuration_api
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
    api_instance = turbinia_configuration_api.TurbiniaConfigurationApi(api_client)

    # example, this endpoint has no required or optional parameters
    try:
        # Read Config
        api_response = api_instance.read_config()
        pprint(api_response)
    except turbinia_api_lib.ApiException as e:
        print("Exception when calling TurbiniaConfigurationApi->read_config: %s\n" % e)
```
### Parameters
This endpoint does not need any parameter.

### Return Types, Responses

Code | Class | Description
------------- | ------------- | -------------
n/a | api_client.ApiResponseWithoutDeserialization | When skip_deserialization is True this response is returned
200 | [ApiResponseFor200](#read_config.ApiResponseFor200) | Successful Response

#### read_config.ApiResponseFor200
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

### Authorization

[oAuth2](../../../README.md#oAuth2)

[[Back to top]](#__pageTop) [[Back to API list]](../../../README.md#documentation-for-api-endpoints) [[Back to Model list]](../../../README.md#documentation-for-models) [[Back to README]](../../../README.md)

