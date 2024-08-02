# CompleteTurbiniaStats

Statistics for different groups of tasks.

## Properties
Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**all_tasks** | **object** |  | [optional] 
**failed_tasks** | **object** |  | [optional] 
**requests** | **object** |  | [optional] 
**successful_tasks** | **object** |  | [optional] 
**tasks_per_type** | **object** |  | [optional] 
**tasks_per_user** | **object** |  | [optional] 
**tasks_per_worker** | **object** |  | [optional] 

## Example

```python
from turbinia_api_lib.models.complete_turbinia_stats import CompleteTurbiniaStats

# TODO update the JSON string below
json = "{}"
# create an instance of CompleteTurbiniaStats from a JSON string
complete_turbinia_stats_instance = CompleteTurbiniaStats.from_json(json)
# print the JSON string representation of the object
print CompleteTurbiniaStats.to_json()

# convert the object into a dict
complete_turbinia_stats_dict = complete_turbinia_stats_instance.to_dict()
# create an instance of CompleteTurbiniaStats from a dict
complete_turbinia_stats_from_dict = CompleteTurbiniaStats.from_dict(complete_turbinia_stats_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


