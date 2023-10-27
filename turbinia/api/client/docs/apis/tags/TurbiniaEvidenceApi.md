<a name="__pageTop"></a>
# turbinia_api_lib.apis.tags.turbinia_evidence_api.TurbiniaEvidenceApi

All URIs are relative to *http://localhost*

Method | HTTP request | Description
------------- | ------------- | -------------
[**get_evidence_attributes**](#get_evidence_attributes) | **get** /api/evidence/types/{evidence_type} | Get Evidence Attributes
[**get_evidence_by_id**](#get_evidence_by_id) | **get** /api/evidence/{evidence_id} | Get Evidence By Id
[**get_evidence_summary**](#get_evidence_summary) | **get** /api/evidence/summary | Get Evidence Summary
[**get_evidence_types**](#get_evidence_types) | **get** /api/evidence/types | Get Evidence Types
[**query_evidence**](#query_evidence) | **get** /api/evidence/query | Query Evidence
[**upload_evidence**](#upload_evidence) | **post** /api/evidence/upload | Upload Evidence

# **get_evidence_attributes**
<a name="get_evidence_attributes"></a>
> bool, date, datetime, dict, float, int, list, str, none_type get_evidence_attributes(evidence_type)

Get Evidence Attributes

Returns supported required parameters for evidence type.  Args:   evidence_type (str): Name of evidence type.

### Example

* OAuth Authentication (oAuth2):
```python
import turbinia_api_lib
from turbinia_api_lib.apis.tags import turbinia_evidence_api
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
    api_instance = turbinia_evidence_api.TurbiniaEvidenceApi(api_client)

    # example passing only required values which don't have defaults set
    path_params = {
        'evidence_type': None,
    }
    try:
        # Get Evidence Attributes
        api_response = api_instance.get_evidence_attributes(
            path_params=path_params,
        )
        pprint(api_response)
    except turbinia_api_lib.ApiException as e:
        print("Exception when calling TurbiniaEvidenceApi->get_evidence_attributes: %s\n" % e)
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
evidence_type | EvidenceTypeSchema | | 

# EvidenceTypeSchema

## Model Type Info
Input Type | Accessed Type | Description | Notes
------------ | ------------- | ------------- | -------------
dict, frozendict.frozendict, str, date, datetime, uuid.UUID, int, float, decimal.Decimal, bool, None, list, tuple, bytes, io.FileIO, io.BufferedReader,  | frozendict.frozendict, str, decimal.Decimal, BoolClass, NoneClass, tuple, bytes, FileIO |  | 

### Return Types, Responses

Code | Class | Description
------------- | ------------- | -------------
n/a | api_client.ApiResponseWithoutDeserialization | When skip_deserialization is True this response is returned
200 | [ApiResponseFor200](#get_evidence_attributes.ApiResponseFor200) | Successful Response
422 | [ApiResponseFor422](#get_evidence_attributes.ApiResponseFor422) | Validation Error

#### get_evidence_attributes.ApiResponseFor200
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

#### get_evidence_attributes.ApiResponseFor422
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

# **get_evidence_by_id**
<a name="get_evidence_by_id"></a>
> bool, date, datetime, dict, float, int, list, str, none_type get_evidence_by_id(evidence_id)

Get Evidence By Id

Retrieves an evidence in Redis by using its UUID.  Args:   evidence_id (str): The UUID of the evidence.  Raises:   HTTPException: if the evidence is not found.  Returns:   Dictionary of the stored evidence

### Example

* OAuth Authentication (oAuth2):
```python
import turbinia_api_lib
from turbinia_api_lib.apis.tags import turbinia_evidence_api
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
    api_instance = turbinia_evidence_api.TurbiniaEvidenceApi(api_client)

    # example passing only required values which don't have defaults set
    path_params = {
        'evidence_id': None,
    }
    try:
        # Get Evidence By Id
        api_response = api_instance.get_evidence_by_id(
            path_params=path_params,
        )
        pprint(api_response)
    except turbinia_api_lib.ApiException as e:
        print("Exception when calling TurbiniaEvidenceApi->get_evidence_by_id: %s\n" % e)
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
evidence_id | EvidenceIdSchema | | 

# EvidenceIdSchema

## Model Type Info
Input Type | Accessed Type | Description | Notes
------------ | ------------- | ------------- | -------------
dict, frozendict.frozendict, str, date, datetime, uuid.UUID, int, float, decimal.Decimal, bool, None, list, tuple, bytes, io.FileIO, io.BufferedReader,  | frozendict.frozendict, str, decimal.Decimal, BoolClass, NoneClass, tuple, bytes, FileIO |  | 

### Return Types, Responses

Code | Class | Description
------------- | ------------- | -------------
n/a | api_client.ApiResponseWithoutDeserialization | When skip_deserialization is True this response is returned
200 | [ApiResponseFor200](#get_evidence_by_id.ApiResponseFor200) | Successful Response
422 | [ApiResponseFor422](#get_evidence_by_id.ApiResponseFor422) | Validation Error

#### get_evidence_by_id.ApiResponseFor200
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

#### get_evidence_by_id.ApiResponseFor422
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

# **get_evidence_summary**
<a name="get_evidence_summary"></a>
> bool, date, datetime, dict, float, int, list, str, none_type get_evidence_summary()

Get Evidence Summary

Retrieves a summary of all evidences in Redis.  Args:   group Optional(str): Attribute used to group summary.   output Optional(str): Sets how the evidence found will be output.   Returns:   summary (dict): Summary of all evidences and their content.  Raises:   HTTPException: if there are no evidences.

### Example

* OAuth Authentication (oAuth2):
```python
import turbinia_api_lib
from turbinia_api_lib.apis.tags import turbinia_evidence_api
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
    api_instance = turbinia_evidence_api.TurbiniaEvidenceApi(api_client)

    # example passing only optional values
    query_params = {
        'group': "_name",
        'output': "keys",
    }
    try:
        # Get Evidence Summary
        api_response = api_instance.get_evidence_summary(
            query_params=query_params,
        )
        pprint(api_response)
    except turbinia_api_lib.ApiException as e:
        print("Exception when calling TurbiniaEvidenceApi->get_evidence_summary: %s\n" % e)
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
group | GroupSchema | | optional
output | OutputSchema | | optional


# GroupSchema

## Model Type Info
Input Type | Accessed Type | Description | Notes
------------ | ------------- | ------------- | -------------
str,  | str,  |  | must be one of ["_name", "cloud_only", "context_dependent", "copyable", "creation_time", "description", "has_child_evidence", "last_update", "local_path", "mount_path", "parent_evidence", "request_id", "resource_id", "resource_tracked", "save_metadata", "saved_path", "saved_path_type", "size", "source", "source_path", "type", ] 

# OutputSchema

## Model Type Info
Input Type | Accessed Type | Description | Notes
------------ | ------------- | ------------- | -------------
str,  | str,  |  | must be one of ["keys", "content", "count", ] if omitted the server will use the default value of "keys"

### Return Types, Responses

Code | Class | Description
------------- | ------------- | -------------
n/a | api_client.ApiResponseWithoutDeserialization | When skip_deserialization is True this response is returned
200 | [ApiResponseFor200](#get_evidence_summary.ApiResponseFor200) | Successful Response
422 | [ApiResponseFor422](#get_evidence_summary.ApiResponseFor422) | Validation Error

#### get_evidence_summary.ApiResponseFor200
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

#### get_evidence_summary.ApiResponseFor422
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

# **get_evidence_types**
<a name="get_evidence_types"></a>
> bool, date, datetime, dict, float, int, list, str, none_type get_evidence_types()

Get Evidence Types

Returns supported Evidence object types and required parameters.

### Example

* OAuth Authentication (oAuth2):
```python
import turbinia_api_lib
from turbinia_api_lib.apis.tags import turbinia_evidence_api
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
    api_instance = turbinia_evidence_api.TurbiniaEvidenceApi(api_client)

    # example, this endpoint has no required or optional parameters
    try:
        # Get Evidence Types
        api_response = api_instance.get_evidence_types()
        pprint(api_response)
    except turbinia_api_lib.ApiException as e:
        print("Exception when calling TurbiniaEvidenceApi->get_evidence_types: %s\n" % e)
```
### Parameters
This endpoint does not need any parameter.

### Return Types, Responses

Code | Class | Description
------------- | ------------- | -------------
n/a | api_client.ApiResponseWithoutDeserialization | When skip_deserialization is True this response is returned
200 | [ApiResponseFor200](#get_evidence_types.ApiResponseFor200) | Successful Response

#### get_evidence_types.ApiResponseFor200
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

# **query_evidence**
<a name="query_evidence"></a>
> bool, date, datetime, dict, float, int, list, str, none_type query_evidence(attribute_value)

Query Evidence

Queries evidence in Redis that have the specified attribute value.  Args:   attribute_name (str): Name of attribute to be queried.   attribute_value (str): Value the attribute must have.   output Optional(str): Sets how the evidence found will be output.  Returns:   summary (dict): Summary of all evidences and their content.  Raises:   HTTPException: If no matching evidence is found.

### Example

* OAuth Authentication (oAuth2):
```python
import turbinia_api_lib
from turbinia_api_lib.apis.tags import turbinia_evidence_api
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
    api_instance = turbinia_evidence_api.TurbiniaEvidenceApi(api_client)

    # example passing only required values which don't have defaults set
    query_params = {
        'attribute_value': "attribute_value_example",
    }
    try:
        # Query Evidence
        api_response = api_instance.query_evidence(
            query_params=query_params,
        )
        pprint(api_response)
    except turbinia_api_lib.ApiException as e:
        print("Exception when calling TurbiniaEvidenceApi->query_evidence: %s\n" % e)

    # example passing only optional values
    query_params = {
        'attribute_name': "request_id",
        'attribute_value': "attribute_value_example",
        'output': "keys",
    }
    try:
        # Query Evidence
        api_response = api_instance.query_evidence(
            query_params=query_params,
        )
        pprint(api_response)
    except turbinia_api_lib.ApiException as e:
        print("Exception when calling TurbiniaEvidenceApi->query_evidence: %s\n" % e)
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
attribute_name | AttributeNameSchema | | optional
attribute_value | AttributeValueSchema | | 
output | OutputSchema | | optional


# AttributeNameSchema

## Model Type Info
Input Type | Accessed Type | Description | Notes
------------ | ------------- | ------------- | -------------
str,  | str,  |  | must be one of ["_name", "cloud_only", "context_dependent", "copyable", "creation_time", "description", "has_child_evidence", "last_update", "local_path", "mount_path", "parent_evidence", "request_id", "resource_id", "resource_tracked", "save_metadata", "saved_path", "saved_path_type", "size", "source", "source_path", "type", "tasks", ] if omitted the server will use the default value of "request_id"

# AttributeValueSchema

## Model Type Info
Input Type | Accessed Type | Description | Notes
------------ | ------------- | ------------- | -------------
str,  | str,  |  | 

# OutputSchema

## Model Type Info
Input Type | Accessed Type | Description | Notes
------------ | ------------- | ------------- | -------------
str,  | str,  |  | must be one of ["keys", "content", "count", ] if omitted the server will use the default value of "keys"

### Return Types, Responses

Code | Class | Description
------------- | ------------- | -------------
n/a | api_client.ApiResponseWithoutDeserialization | When skip_deserialization is True this response is returned
200 | [ApiResponseFor200](#query_evidence.ApiResponseFor200) | Successful Response
422 | [ApiResponseFor422](#query_evidence.ApiResponseFor422) | Validation Error

#### query_evidence.ApiResponseFor200
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

#### query_evidence.ApiResponseFor422
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

# **upload_evidence**
<a name="upload_evidence"></a>
> bool, date, datetime, dict, float, int, list, str, none_type upload_evidence()

Upload Evidence

Upload evidence file to server for processing.  Args:   ticket_id (str): ID of the ticket, which will be the name of the folder      where the evidence will be saved.   calculate_hash (bool): Boolean defining if the hash of the evidence should     be calculated.   file (List[UploadFile]): Evidence files to be uploaded to folder for later       processing. The maximum size of the file is 10 GB.   Returns:   List of uploaded evidences or warning messages if any.

### Example

* OAuth Authentication (oAuth2):
```python
import turbinia_api_lib
from turbinia_api_lib.apis.tags import turbinia_evidence_api
from turbinia_api_lib.model.body_upload_evidence_api_evidence_upload_post import BodyUploadEvidenceApiEvidenceUploadPost
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
    api_instance = turbinia_evidence_api.TurbiniaEvidenceApi(api_client)

    # example passing only optional values
    body = dict(
        calculate_hash=False,
        files=[
            open('/path/to/file', 'rb')
        ],
        ticket_id="ticket_id_example",
    )
    try:
        # Upload Evidence
        api_response = api_instance.upload_evidence(
            body=body,
        )
        pprint(api_response)
    except turbinia_api_lib.ApiException as e:
        print("Exception when calling TurbiniaEvidenceApi->upload_evidence: %s\n" % e)
```
### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
body | typing.Union[SchemaForRequestBodyMultipartFormData, Unset] | optional, default is unset |
content_type | str | optional, default is 'multipart/form-data' | Selects the schema and serialization of the request body
accept_content_types | typing.Tuple[str] | default is ('application/json', ) | Tells the server the content type(s) that are accepted by the client
stream | bool | default is False | if True then the response.content will be streamed and loaded from a file like object. When downloading a file, set this to True to force the code to deserialize the content to a FileSchema file
timeout | typing.Optional[typing.Union[int, typing.Tuple]] | default is None | the timeout used by the rest client
skip_deserialization | bool | default is False | when True, headers and body will be unset and an instance of api_client.ApiResponseWithoutDeserialization will be returned

### body

# SchemaForRequestBodyMultipartFormData
Type | Description  | Notes
------------- | ------------- | -------------
[**BodyUploadEvidenceApiEvidenceUploadPost**](../../models/BodyUploadEvidenceApiEvidenceUploadPost.md) |  | 


### Return Types, Responses

Code | Class | Description
------------- | ------------- | -------------
n/a | api_client.ApiResponseWithoutDeserialization | When skip_deserialization is True this response is returned
200 | [ApiResponseFor200](#upload_evidence.ApiResponseFor200) | Successful Response
422 | [ApiResponseFor422](#upload_evidence.ApiResponseFor422) | Validation Error

#### upload_evidence.ApiResponseFor200
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

#### upload_evidence.ApiResponseFor422
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

