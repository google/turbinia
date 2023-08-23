# ValidationError


## Properties
Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**loc** | **object** |  | 
**msg** | **object** |  | 
**type** | **object** |  | 

## Example

```python
from turbinia_api_lib.models.validation_error import ValidationError

# TODO update the JSON string below
json = "{}"
# create an instance of ValidationError from a JSON string
validation_error_instance = ValidationError.from_json(json)
# print the JSON string representation of the object
print ValidationError.to_json()

# convert the object into a dict
validation_error_dict = validation_error_instance.to_dict()
# create an instance of ValidationError from a dict
validation_error_form_dict = validation_error.from_dict(validation_error_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


