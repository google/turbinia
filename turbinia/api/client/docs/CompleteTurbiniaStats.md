# CompleteTurbiniaStats

Statistics for different groups of tasks.

## Properties
Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**all_tasks** | **object** |  | 
**failed_tasks** | **object** |  | 
**requests** | **object** |  | 
**successful_tasks** | **object** |  | 
**tasks_per_type** | **object** |  | 
**tasks_per_user** | **object** |  | 
**tasks_per_worker** | **object** |  | 

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
complete_turbinia_stats_form_dict = complete_turbinia_stats.from_dict(complete_turbinia_stats_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


