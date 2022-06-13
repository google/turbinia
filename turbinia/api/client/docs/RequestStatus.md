# RequestStatus

Represents a Turbinia request status object.

## Properties
Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**failed_tasks** | **int** |  | [optional]  if omitted the server will use the default value of 0
**last_task_update_time** | **str** |  | [optional] 
**reason** | **str** |  | [optional] 
**request_id** | **str** |  | [optional] 
**requester** | **str** |  | [optional] 
**running_tasks** | **int** |  | [optional]  if omitted the server will use the default value of 0
**status** | **str** |  | [optional] 
**successful_tasks** | **int** |  | [optional]  if omitted the server will use the default value of 0
**task_count** | **int** |  | [optional]  if omitted the server will use the default value of 0
**tasks** | **[{str: (bool, date, datetime, dict, float, int, list, str, none_type)}]** |  | [optional]  if omitted the server will use the default value of []
**any string name** | **bool, date, datetime, dict, float, int, list, str, none_type** | any string name can be used but the value must be the correct type | [optional]

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


