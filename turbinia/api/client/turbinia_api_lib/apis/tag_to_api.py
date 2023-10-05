import typing_extensions

from turbinia_api_lib.apis.tags import TagValues
from turbinia_api_lib.apis.tags.turbinia_configuration_api import TurbiniaConfigurationApi
from turbinia_api_lib.apis.tags.turbinia_evidence_api import TurbiniaEvidenceApi
from turbinia_api_lib.apis.tags.turbinia_jobs_api import TurbiniaJobsApi
from turbinia_api_lib.apis.tags.turbinia_logs_api import TurbiniaLogsApi
from turbinia_api_lib.apis.tags.turbinia_request_results_api import TurbiniaRequestResultsApi
from turbinia_api_lib.apis.tags.turbinia_requests_api import TurbiniaRequestsApi
from turbinia_api_lib.apis.tags.turbinia_tasks_api import TurbiniaTasksApi

TagToApi = typing_extensions.TypedDict(
    'TagToApi',
    {
        TagValues.TURBINIA_CONFIGURATION: TurbiniaConfigurationApi,
        TagValues.TURBINIA_EVIDENCE: TurbiniaEvidenceApi,
        TagValues.TURBINIA_JOBS: TurbiniaJobsApi,
        TagValues.TURBINIA_LOGS: TurbiniaLogsApi,
        TagValues.TURBINIA_REQUEST_RESULTS: TurbiniaRequestResultsApi,
        TagValues.TURBINIA_REQUESTS: TurbiniaRequestsApi,
        TagValues.TURBINIA_TASKS: TurbiniaTasksApi,
    }
)

tag_to_api = TagToApi(
    {
        TagValues.TURBINIA_CONFIGURATION: TurbiniaConfigurationApi,
        TagValues.TURBINIA_EVIDENCE: TurbiniaEvidenceApi,
        TagValues.TURBINIA_JOBS: TurbiniaJobsApi,
        TagValues.TURBINIA_LOGS: TurbiniaLogsApi,
        TagValues.TURBINIA_REQUEST_RESULTS: TurbiniaRequestResultsApi,
        TagValues.TURBINIA_REQUESTS: TurbiniaRequestsApi,
        TagValues.TURBINIA_TASKS: TurbiniaTasksApi,
    }
)
