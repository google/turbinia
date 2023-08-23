# BaseRequestOptions

Base Request Options class to be extended by other option types. 

## Properties
Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**filter_patterns** | **object** |  | [optional] 
**group_id** | **object** |  | [optional] 
**jobs_allowlist** | **object** |  | [optional] 
**jobs_denylist** | **object** |  | [optional] 
**reason** | **object** |  | [optional] 
**recipe_data** | **object** |  | [optional] 
**recipe_name** | **object** |  | [optional] 
**request_id** | **object** |  | [optional] 
**requester** | **object** |  | [optional] 
**sketch_id** | **object** |  | [optional] 
**yara_rules** | **object** |  | [optional] 

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
base_request_options_form_dict = base_request_options.from_dict(base_request_options_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


