# turbinia_api_lib.model.base_request_options.BaseRequestOptions

Base Request Options class to be extended by other option types. 

## Model Type Info
Input Type | Accessed Type | Description | Notes
------------ | ------------- | ------------- | -------------
dict, frozendict.frozendict,  | frozendict.frozendict,  | Base Request Options class to be extended by other option types.  | 

### Dictionary Keys
Key | Input Type | Accessed Type | Description | Notes
------------ | ------------- | ------------- | ------------- | -------------
**[filter_patterns](#filter_patterns)** | list, tuple,  | tuple,  |  | [optional] 
**group_id** | str,  | str,  |  | [optional] 
**[jobs_allowlist](#jobs_allowlist)** | list, tuple,  | tuple,  |  | [optional] 
**[jobs_denylist](#jobs_denylist)** | list, tuple,  | tuple,  |  | [optional] 
**reason** | str,  | str,  |  | [optional] 
**recipe_data** | str,  | str,  |  | [optional] 
**recipe_name** | str,  | str,  |  | [optional] 
**request_id** | str,  | str,  |  | [optional] 
**requester** | str,  | str,  |  | [optional] 
**sketch_id** | decimal.Decimal, int,  | decimal.Decimal,  |  | [optional] 
**yara_rules** | str,  | str,  |  | [optional] 
**any_string_name** | dict, frozendict.frozendict, str, date, datetime, int, float, bool, decimal.Decimal, None, list, tuple, bytes, io.FileIO, io.BufferedReader | frozendict.frozendict, str, BoolClass, decimal.Decimal, NoneClass, tuple, bytes, FileIO | any string name can be used but the value must be the correct type | [optional]

# filter_patterns

## Model Type Info
Input Type | Accessed Type | Description | Notes
------------ | ------------- | ------------- | -------------
list, tuple,  | tuple,  |  | 

### Tuple Items
Class Name | Input Type | Accessed Type | Description | Notes
------------- | ------------- | ------------- | ------------- | -------------
items | str,  | str,  |  | 

# jobs_allowlist

## Model Type Info
Input Type | Accessed Type | Description | Notes
------------ | ------------- | ------------- | -------------
list, tuple,  | tuple,  |  | 

### Tuple Items
Class Name | Input Type | Accessed Type | Description | Notes
------------- | ------------- | ------------- | ------------- | -------------
items | str,  | str,  |  | 

# jobs_denylist

## Model Type Info
Input Type | Accessed Type | Description | Notes
------------ | ------------- | ------------- | -------------
list, tuple,  | tuple,  |  | 

### Tuple Items
Class Name | Input Type | Accessed Type | Description | Notes
------------- | ------------- | ------------- | ------------- | -------------
items | str,  | str,  |  | 

[[Back to Model list]](../../README.md#documentation-for-models) [[Back to API list]](../../README.md#documentation-for-api-endpoints) [[Back to README]](../../README.md)

