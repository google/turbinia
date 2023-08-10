# turbinia_api_lib.TurbiniaEvidenceApi

All URIs are relative to *http://localhost*

Method | HTTP request | Description
------------- | ------------- | -------------
[**get_evidence_attributes**](TurbiniaEvidenceApi.md#get_evidence_attributes) | **GET** /api/evidence/types/{evidence_type} | Get Evidence Attributes
[**get_evidence_by_id**](TurbiniaEvidenceApi.md#get_evidence_by_id) | **GET** /api/evidence/{evidence_id} | Get Evidence By Id
[**get_evidence_summary**](TurbiniaEvidenceApi.md#get_evidence_summary) | **GET** /api/evidence/summary | Get Evidence Summary
[**get_evidence_types**](TurbiniaEvidenceApi.md#get_evidence_types) | **GET** /api/evidence/types | Get Evidence Types
[**query_evidence**](TurbiniaEvidenceApi.md#query_evidence) | **GET** /api/evidence/query | Query Evidence
[**upload_evidence**](TurbiniaEvidenceApi.md#upload_evidence) | **POST** /api/evidence/upload | Upload Evidence


# **get_evidence_attributes**
> object get_evidence_attributes(evidence_type)

Get Evidence Attributes

Returns supported Evidence object types and required parameters.  Args:   evidence_type (str): Name of evidence type.

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
    api_instance = turbinia_api_lib.TurbiniaEvidenceApi(api_client)
    evidence_type = None # object | 

    try:
        # Get Evidence Attributes
        api_response = api_instance.get_evidence_attributes(evidence_type)
        print("The response of TurbiniaEvidenceApi->get_evidence_attributes:\n")
        pprint(api_response)
    except Exception as e:
        print("Exception when calling TurbiniaEvidenceApi->get_evidence_attributes: %s\n" % e)
```


### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **evidence_type** | [**object**](.md)|  | 

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

# **get_evidence_by_id**
> object get_evidence_by_id(evidence_id)

Get Evidence By Id

Retrieves an evidence in redis by using its UUID.  Args:   evidence_id (str): The UUID of the evidence.  Raises:   HTTPException: if the evidence is not found.  Returns:

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
    api_instance = turbinia_api_lib.TurbiniaEvidenceApi(api_client)
    evidence_id = None # object | 

    try:
        # Get Evidence By Id
        api_response = api_instance.get_evidence_by_id(evidence_id)
        print("The response of TurbiniaEvidenceApi->get_evidence_by_id:\n")
        pprint(api_response)
    except Exception as e:
        print("Exception when calling TurbiniaEvidenceApi->get_evidence_by_id: %s\n" % e)
```


### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **evidence_id** | [**object**](.md)|  | 

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

# **get_evidence_summary**
> object get_evidence_summary(sort=sort, output=output)

Get Evidence Summary

Retrieves a summary of all evidences in redis.  Args:   sort Optional(str): Attribute used to sort summary.  Returns:   summary (dict): Summary of all evidences and their content.  Raises:   HTTPException: if there are no evidences.

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
    api_instance = turbinia_api_lib.TurbiniaEvidenceApi(api_client)
    sort = None # object |  (optional)
    output = None # object |  (optional)

    try:
        # Get Evidence Summary
        api_response = api_instance.get_evidence_summary(sort=sort, output=output)
        print("The response of TurbiniaEvidenceApi->get_evidence_summary:\n")
        pprint(api_response)
    except Exception as e:
        print("Exception when calling TurbiniaEvidenceApi->get_evidence_summary: %s\n" % e)
```


### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **sort** | [**object**](.md)|  | [optional] 
 **output** | [**object**](.md)|  | [optional] 

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

# **get_evidence_types**
> object get_evidence_types()

Get Evidence Types

Returns supported Evidence object types and required parameters.

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
    api_instance = turbinia_api_lib.TurbiniaEvidenceApi(api_client)

    try:
        # Get Evidence Types
        api_response = api_instance.get_evidence_types()
        print("The response of TurbiniaEvidenceApi->get_evidence_types:\n")
        pprint(api_response)
    except Exception as e:
        print("Exception when calling TurbiniaEvidenceApi->get_evidence_types: %s\n" % e)
```


### Parameters
This endpoint does not need any parameter.

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

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **query_evidence**
> object query_evidence(value, attribute_name=attribute_name, output=output)

Query Evidence

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
    api_instance = turbinia_api_lib.TurbiniaEvidenceApi(api_client)
    value = None # object | 
    attribute_name = None # object |  (optional)
    output = None # object |  (optional)

    try:
        # Query Evidence
        api_response = api_instance.query_evidence(value, attribute_name=attribute_name, output=output)
        print("The response of TurbiniaEvidenceApi->query_evidence:\n")
        pprint(api_response)
    except Exception as e:
        print("Exception when calling TurbiniaEvidenceApi->query_evidence: %s\n" % e)
```


### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **value** | [**object**](.md)|  | 
 **attribute_name** | [**object**](.md)|  | [optional] 
 **output** | [**object**](.md)|  | [optional] 

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

# **upload_evidence**
> object upload_evidence(files)

Upload Evidence

Upload evidence file to server for processing.  Args:   file (List[UploadFile]): Evidence file to be uploaded to folder for later       processing. The maximum size of the file is 10 GB.   Raises:   TypeError: If pre-conditions are not met.  Returns:   List of uploaded evidences or warning messages if any.

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
    api_instance = turbinia_api_lib.TurbiniaEvidenceApi(api_client)
    files = None # object | 

    try:
        # Upload Evidence
        api_response = api_instance.upload_evidence(files)
        print("The response of TurbiniaEvidenceApi->upload_evidence:\n")
        pprint(api_response)
    except Exception as e:
        print("Exception when calling TurbiniaEvidenceApi->upload_evidence: %s\n" % e)
```


### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **files** | [**object**](object.md)|  | 

### Return type

**object**

### Authorization

[oAuth2](../README.md#oAuth2)

### HTTP request headers

 - **Content-Type**: multipart/form-data
 - **Accept**: application/json

### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
**200** | Successful Response |  -  |
**422** | Validation Error |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

