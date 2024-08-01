# BaseRequestOptions

Base Request Options class to be extended by other option types. 

## Properties
Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**filter_patterns** | **List[str]** |  | [optional] 
**group_id** | **str** |  | [optional] 
**jobs_allowlist** | **List[str]** |  | [optional] 
**jobs_denylist** | **List[str]** |  | [optional] 
**reason** | **str** |  | [optional] 
**recipe_data** | **str** |  | [optional] 
**recipe_name** | **str** |  | [optional] 
**request_id** | **str** |  | [optional] 
**requester** | **str** |  | [optional] 
**sketch_id** | **int** |  | [optional] 
**yara_rules** | **str** |  | [optional] 

## Example

```python
from turbinia_api_lib.models.base_request_options import BaseRequestOptions

# TODO update the JSON string below
json = "{}"
# create an instance of BaseRequestOptions from a JSON string
base_request_options_instance = BaseRequestOptions.from_json(json)
# print the JSON string representation of the object
print BaseRequestOptions.to_json()

# convert the object into a dict
base_request_options_dict = base_request_options_instance.to_dict()
# create an instance of BaseRequestOptions from a dict
base_request_options_from_dict = BaseRequestOptions.from_dict(base_request_options_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


