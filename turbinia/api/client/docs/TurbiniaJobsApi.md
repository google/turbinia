# turbinia_api_client.TurbiniaJobsApi

All URIs are relative to *http://localhost*

Method | HTTP request | Description
------------- | ------------- | -------------
[**read_jobs**](TurbiniaJobsApi.md#read_jobs) | **GET** /jobs/ | Read Jobs


# **read_jobs**
> bool, date, datetime, dict, float, int, list, str, none_type read_jobs()

Read Jobs

Return all available jobs.

### Example


```python
import time
import turbinia_api_client
from turbinia_api_client.api import turbinia_jobs_api
from pprint import pprint
# Defining the host is optional and defaults to http://localhost
# See configuration.py for a list of all supported configuration parameters.
configuration = turbinia_api_client.Configuration(
    host = "http://localhost"
)


# Enter a context with an instance of the API client
with turbinia_api_client.ApiClient() as api_client:
    # Create an instance of the API class
    api_instance = turbinia_jobs_api.TurbiniaJobsApi(api_client)

    # example, this endpoint has no required or optional parameters
    try:
        # Read Jobs
        api_response = api_instance.read_jobs()
        pprint(api_response)
    except turbinia_api_client.ApiException as e:
        print("Exception when calling TurbiniaJobsApi->read_jobs: %s\n" % e)
```


### Parameters
This endpoint does not need any parameter.

### Return type

**bool, date, datetime, dict, float, int, list, str, none_type**

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json


### HTTP response details

| Status code | Description | Response headers |
|-------------|-------------|------------------|
**200** | Successful Response |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

