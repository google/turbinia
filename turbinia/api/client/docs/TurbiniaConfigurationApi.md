# turbinia_api_client.TurbiniaConfigurationApi

All URIs are relative to *http://localhost*

Method | HTTP request | Description
------------- | ------------- | -------------
[**read_config**](TurbiniaConfigurationApi.md#read_config) | **GET** /api/config/ | Read Config


# **read_config**
> bool, date, datetime, dict, float, int, list, str, none_type read_config()

Read Config

Retrieve turbinia config.

### Example

* OAuth Authentication (oAuth2):

```python
import time
import turbinia_api_client
from turbinia_api_client.api import turbinia_configuration_api
from pprint import pprint
# Defining the host is optional and defaults to http://localhost
# See configuration.py for a list of all supported configuration parameters.
configuration = turbinia_api_client.Configuration(
    host = "http://localhost"
)

# The client must configure the authentication and authorization parameters
# in accordance with the API server security policy.
# Examples for each auth method are provided below, use the example that
# satisfies your auth use case.

# Configure OAuth2 access token for authorization: oAuth2
configuration = turbinia_api_client.Configuration(
    host = "http://localhost"
)
configuration.access_token = 'YOUR_ACCESS_TOKEN'

# Enter a context with an instance of the API client
with turbinia_api_client.ApiClient(configuration) as api_client:
    # Create an instance of the API class
    api_instance = turbinia_configuration_api.TurbiniaConfigurationApi(api_client)

    # example, this endpoint has no required or optional parameters
    try:
        # Read Config
        api_response = api_instance.read_config()
        pprint(api_response)
    except turbinia_api_client.ApiException as e:
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
