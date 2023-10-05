import typing_extensions

from turbinia_api_lib.paths import PathValues
from turbinia_api_lib.apis.paths.api_config_ import ApiConfig
from turbinia_api_lib.apis.paths.api_config_request_options import ApiConfigRequestOptions
from turbinia_api_lib.apis.paths.api_evidence_query import ApiEvidenceQuery
from turbinia_api_lib.apis.paths.api_evidence_summary import ApiEvidenceSummary
from turbinia_api_lib.apis.paths.api_evidence_types import ApiEvidenceTypes
from turbinia_api_lib.apis.paths.api_evidence_types_evidence_type import ApiEvidenceTypesEvidenceType
from turbinia_api_lib.apis.paths.api_evidence_upload import ApiEvidenceUpload
from turbinia_api_lib.apis.paths.api_evidence_evidence_id import ApiEvidenceEvidenceId
from turbinia_api_lib.apis.paths.api_jobs_ import ApiJobs
from turbinia_api_lib.apis.paths.api_logs_query import ApiLogsQuery
from turbinia_api_lib.apis.paths.api_request_ import ApiRequest
from turbinia_api_lib.apis.paths.api_request_summary import ApiRequestSummary
from turbinia_api_lib.apis.paths.api_request_request_id import ApiRequestRequestId
from turbinia_api_lib.apis.paths.api_result_request_request_id import ApiResultRequestRequestId
from turbinia_api_lib.apis.paths.api_result_task_task_id import ApiResultTaskTaskId
from turbinia_api_lib.apis.paths.api_task_statistics import ApiTaskStatistics
from turbinia_api_lib.apis.paths.api_task_workers import ApiTaskWorkers
from turbinia_api_lib.apis.paths.api_task_task_id import ApiTaskTaskId

PathToApi = typing_extensions.TypedDict(
    'PathToApi',
    {
        PathValues.API_CONFIG_: ApiConfig,
        PathValues.API_CONFIG_REQUEST_OPTIONS: ApiConfigRequestOptions,
        PathValues.API_EVIDENCE_QUERY: ApiEvidenceQuery,
        PathValues.API_EVIDENCE_SUMMARY: ApiEvidenceSummary,
        PathValues.API_EVIDENCE_TYPES: ApiEvidenceTypes,
        PathValues.API_EVIDENCE_TYPES_EVIDENCE_TYPE: ApiEvidenceTypesEvidenceType,
        PathValues.API_EVIDENCE_UPLOAD: ApiEvidenceUpload,
        PathValues.API_EVIDENCE_EVIDENCE_ID: ApiEvidenceEvidenceId,
        PathValues.API_JOBS_: ApiJobs,
        PathValues.API_LOGS_QUERY: ApiLogsQuery,
        PathValues.API_REQUEST_: ApiRequest,
        PathValues.API_REQUEST_SUMMARY: ApiRequestSummary,
        PathValues.API_REQUEST_REQUEST_ID: ApiRequestRequestId,
        PathValues.API_RESULT_REQUEST_REQUEST_ID: ApiResultRequestRequestId,
        PathValues.API_RESULT_TASK_TASK_ID: ApiResultTaskTaskId,
        PathValues.API_TASK_STATISTICS: ApiTaskStatistics,
        PathValues.API_TASK_WORKERS: ApiTaskWorkers,
        PathValues.API_TASK_TASK_ID: ApiTaskTaskId,
    }
)

path_to_api = PathToApi(
    {
        PathValues.API_CONFIG_: ApiConfig,
        PathValues.API_CONFIG_REQUEST_OPTIONS: ApiConfigRequestOptions,
        PathValues.API_EVIDENCE_QUERY: ApiEvidenceQuery,
        PathValues.API_EVIDENCE_SUMMARY: ApiEvidenceSummary,
        PathValues.API_EVIDENCE_TYPES: ApiEvidenceTypes,
        PathValues.API_EVIDENCE_TYPES_EVIDENCE_TYPE: ApiEvidenceTypesEvidenceType,
        PathValues.API_EVIDENCE_UPLOAD: ApiEvidenceUpload,
        PathValues.API_EVIDENCE_EVIDENCE_ID: ApiEvidenceEvidenceId,
        PathValues.API_JOBS_: ApiJobs,
        PathValues.API_LOGS_QUERY: ApiLogsQuery,
        PathValues.API_REQUEST_: ApiRequest,
        PathValues.API_REQUEST_SUMMARY: ApiRequestSummary,
        PathValues.API_REQUEST_REQUEST_ID: ApiRequestRequestId,
        PathValues.API_RESULT_REQUEST_REQUEST_ID: ApiResultRequestRequestId,
        PathValues.API_RESULT_TASK_TASK_ID: ApiResultTaskTaskId,
        PathValues.API_TASK_STATISTICS: ApiTaskStatistics,
        PathValues.API_TASK_WORKERS: ApiTaskWorkers,
        PathValues.API_TASK_TASK_ID: ApiTaskTaskId,
    }
)
