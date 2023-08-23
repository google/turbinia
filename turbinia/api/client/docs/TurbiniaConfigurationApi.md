# turbinia_api_lib.TurbiniaConfigurationApi

All URIs are relative to *http://localhost*

Method | HTTP request | Description
------------- | ------------- | -------------
[**get_evidence_attributes_by_name**](TurbiniaConfigurationApi.md#get_evidence_attributes_by_name) | **GET** /api/config/evidence/{evidence_name} | Get Evidence Attributes By Name
[**get_evidence_types**](TurbiniaConfigurationApi.md#get_evidence_types) | **GET** /api/config/evidence | Get Evidence Types
[**get_request_options**](TurbiniaConfigurationApi.md#get_request_options) | **GET** /api/config/request_options | Get Request Options
[**read_config**](TurbiniaConfigurationApi.md#read_config) | **GET** /api/config/ | Read Config


# **get_evidence_attributes_by_name**
> bool, date, datetime, dict, float, int, list, str, none_type get_evidence_attributes_by_name(evidence_name)

Get Evidence Attributes By Name

Returns supported Evidence object types and required parameters.

### Example

* OAuth Authentication (oAuth2):

```python
import time
import turbinia_api_lib
from turbinia_api_lib.api import turbinia_configuration_api
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
    host = "http://localhost"
)
configuration.access_token = 'YOUR_ACCESS_TOKEN'

# Enter a context with an instance of the API client
with turbinia_api_lib.ApiClient(configuration) as api_client:
    # Create an instance of the API class
    api_instance = turbinia_configuration_api.TurbiniaConfigurationApi(api_client)
    evidence_name = None # bool, date, datetime, dict, float, int, list, str, none_type | 

    # example passing only required values which don't have defaults set
    try:
        # Get Evidence Attributes By Name
        api_response = api_instance.get_evidence_attributes_by_name(evidence_name)
        pprint(api_response)
    except turbinia_api_lib.ApiException as e:
        print("Exception when calling TurbiniaConfigurationApi->get_evidence_attributes_by_name: %s\n" % e)
```


### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **evidence_name** | **bool, date, datetime, dict, float, int, list, str, none_type**|  |

### Return type

**bool, date, datetime, dict, float, int, list, str, none_type**

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
> bool, date, datetime, dict, float, int, list, str, none_type get_evidence_types()

Get Evidence Types

Returns supported Evidence object types and required parameters.

### Example

* OAuth Authentication (oAuth2):

```python
import time
import turbinia_api_lib
from turbinia_api_lib.api import turbinia_configuration_api
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
    host = "http://localhost"
)
configuration.access_token = 'YOUR_ACCESS_TOKEN'

# Enter a context with an instance of the API client
with turbinia_api_lib.ApiClient(configuration) as api_client:
    # Create an instance of the API class
    api_instance = turbinia_configuration_api.TurbiniaConfigurationApi(api_client)

    # example, this endpoint has no required or optional parameters
    try:
        # Get Evidence Types
        api_response = api_instance.get_evidence_types()
        pprint(api_response)
    except turbinia_api_lib.ApiException as e:
        print("Exception when calling TurbiniaConfigurationApi->get_evidence_types: %s\n" % e)
```


### Parameters
This endpoint does not need any parameter.

### Return type

**bool, date, datetime, dict, float, int, list, str, none_type**

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

# **get_request_options**
> bool, date, datetime, dict, float, int, list, str, none_type get_request_options()

Get Request Options

Returns a list BaseRequestOptions attributes.

### Example

* OAuth Authentication (oAuth2):

```python
import time
import turbinia_api_lib
from turbinia_api_lib.api import turbinia_configuration_api
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
    host = "http://localhost"
)
configuration.access_token = 'YOUR_ACCESS_TOKEN'

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

### Return type

**bool, date, datetime, dict, float, int, list, str, none_type**

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

# **read_config**
> bool, date, datetime, dict, float, int, list, str, none_type read_config()

Read Config

Retrieve turbinia config.

### Example

* OAuth Authentication (oAuth2):

```python
import time
import turbinia_api_lib
from turbinia_api_lib.api import turbinia_configuration_api
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
    host = "http://localhost"
)
configuration.access_token = 'YOUR_ACCESS_TOKEN'

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

### Return type

**bool, date, datetime, dict, float, int, list, str, none_type**

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

