# turbinia_api_lib.TurbiniaJobsApi

All URIs are relative to *http://localhost*

Method | HTTP request | Description
------------- | ------------- | -------------
[**read_jobs**](TurbiniaJobsApi.md#read_jobs) | **GET** /api/jobs/ | Read Jobs


# **read_jobs**
> object read_jobs()

Read Jobs

Return enabled jobs from the current Turbinia config.

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
    api_instance = turbinia_api_lib.TurbiniaJobsApi(api_client)

    try:
        # Read Jobs
        api_response = api_instance.read_jobs()
        print("The response of TurbiniaJobsApi->read_jobs:\n")
        pprint(api_response)
    except Exception as e:
        print("Exception when calling TurbiniaJobsApi->read_jobs: %s\n" % e)
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

