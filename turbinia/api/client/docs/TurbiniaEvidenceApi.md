# turbinia_api_lib.TurbiniaEvidenceApi

All URIs are relative to *http://localhost*

Method | HTTP request | Description
------------- | ------------- | -------------
[**download_by_evidence_id**](TurbiniaEvidenceApi.md#download_by_evidence_id) | **GET** /api/evidence/download/{evidence_id} | Download By Evidence Id
[**get_evidence_attributes**](TurbiniaEvidenceApi.md#get_evidence_attributes) | **GET** /api/evidence/types/{evidence_type} | Get Evidence Attributes
[**get_evidence_by_id**](TurbiniaEvidenceApi.md#get_evidence_by_id) | **GET** /api/evidence/{evidence_id} | Get Evidence By Id
[**get_evidence_summary**](TurbiniaEvidenceApi.md#get_evidence_summary) | **GET** /api/evidence/summary | Get Evidence Summary
[**get_evidence_types**](TurbiniaEvidenceApi.md#get_evidence_types) | **GET** /api/evidence/types | Get Evidence Types
[**query_evidence**](TurbiniaEvidenceApi.md#query_evidence) | **GET** /api/evidence/query | Query Evidence
[**upload_evidence**](TurbiniaEvidenceApi.md#upload_evidence) | **POST** /api/evidence/upload | Upload Evidence


# **download_by_evidence_id**
> bytearray download_by_evidence_id(evidence_id)

Download By Evidence Id

Retrieves an evidence in Redis by using its UUID.  Args:   evidence_id (str): The UUID of the evidence.  Raises:   HTTPException: if the evidence is not found.  Returns:   FileResponse: The evidence file.

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
        # Download By Evidence Id
        api_response = api_instance.download_by_evidence_id(evidence_id)
        print("The response of TurbiniaEvidenceApi->download_by_evidence_id:\n")
        pprint(api_response)
    except Exception as e:
        print("Exception when calling TurbiniaEvidenceApi->download_by_evidence_id: %s\n" % e)
```



### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **evidence_id** | [**object**](.md)|  | 

### Return type

**bytearray**

### Authorization

[oAuth2](../README.md#oAuth2)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/octet-stream, application/json

### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
**200** | Successful Response |  -  |
**422** | Validation Error |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **get_evidence_attributes**
> object get_evidence_attributes(evidence_type)

Get Evidence Attributes

Returns supported required parameters for evidence type.  Args:   evidence_type (str): Name of evidence type.

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

Retrieves an evidence in Redis by using its UUID.  Args:   evidence_id (str): The UUID of the evidence.  Raises:   HTTPException: if the evidence is not found.  Returns:   Dictionary of the stored evidence

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
> object get_evidence_summary(group=group, output=output)

Get Evidence Summary

Retrieves a summary of all evidences in Redis.  Args:   group Optional(str): Attribute used to group summary.   output Optional(str): Sets how the evidence found will be output.   Returns:   summary (dict): Summary of all evidences and their content.  Raises:   HTTPException: if there are no evidences.

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
    group = 'group_example' # str |  (optional)
    output = 'keys' # str |  (optional) (default to 'keys')

    try:
        # Get Evidence Summary
        api_response = api_instance.get_evidence_summary(group=group, output=output)
        print("The response of TurbiniaEvidenceApi->get_evidence_summary:\n")
        pprint(api_response)
    except Exception as e:
        print("Exception when calling TurbiniaEvidenceApi->get_evidence_summary: %s\n" % e)
```



### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **group** | **str**|  | [optional] 
 **output** | **str**|  | [optional] [default to &#39;keys&#39;]

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
> object query_evidence(attribute_value, attribute_name=attribute_name, output=output)

Query Evidence

Queries evidence in Redis that have the specified attribute value.  Args:   attribute_name (str): Name of attribute to be queried.   attribute_value (str): Value the attribute must have.   output Optional(str): Sets how the evidence found will be output.  Returns:   summary (dict): Summary of all evidences and their content.  Raises:   HTTPException: If no matching evidence is found.

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
    attribute_value = 'attribute_value_example' # str | 
    attribute_name = 'request_id' # str |  (optional) (default to 'request_id')
    output = 'keys' # str |  (optional) (default to 'keys')

    try:
        # Query Evidence
        api_response = api_instance.query_evidence(attribute_value, attribute_name=attribute_name, output=output)
        print("The response of TurbiniaEvidenceApi->query_evidence:\n")
        pprint(api_response)
    except Exception as e:
        print("Exception when calling TurbiniaEvidenceApi->query_evidence: %s\n" % e)
```



### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **attribute_value** | **str**|  | 
 **attribute_name** | **str**|  | [optional] [default to &#39;request_id&#39;]
 **output** | **str**|  | [optional] [default to &#39;keys&#39;]

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
> object upload_evidence(files, ticket_id, calculate_hash=calculate_hash)

Upload Evidence

Upload evidence file to server for processing.  Args:   ticket_id (str): ID of the ticket, which will be the name of the folder      where the evidence will be saved.   calculate_hash (bool): Boolean defining if the hash of the evidence should     be calculated.   file (List[UploadFile]): Evidence files to be uploaded to folder for later       processing. The maximum size of the file is 10 GB.   Returns:   List of uploaded evidences or warning messages if any.

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
    files = None # List[bytearray] | 
    ticket_id = 'ticket_id_example' # str | 
    calculate_hash = False # bool |  (optional) (default to False)

    try:
        # Upload Evidence
        api_response = api_instance.upload_evidence(files, ticket_id, calculate_hash=calculate_hash)
        print("The response of TurbiniaEvidenceApi->upload_evidence:\n")
        pprint(api_response)
    except Exception as e:
        print("Exception when calling TurbiniaEvidenceApi->upload_evidence: %s\n" % e)
```



### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **files** | **List[bytearray]**|  | 
 **ticket_id** | **str**|  | 
 **calculate_hash** | **bool**|  | [optional] [default to False]

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

