# do not import all endpoints into this module because that uses a lot of memory and stack frames
# if you need the ability to import all endpoints from this module, import them with
# from turbinia_api_lib.apis.path_to_api import path_to_api

import enum


class PathValues(str, enum.Enum):
    API_CONFIG_ = "/api/config/"
    API_CONFIG_REQUEST_OPTIONS = "/api/config/request_options"
    API_EVIDENCE_QUERY = "/api/evidence/query"
    API_EVIDENCE_SUMMARY = "/api/evidence/summary"
    API_EVIDENCE_TYPES = "/api/evidence/types"
    API_EVIDENCE_TYPES_EVIDENCE_TYPE = "/api/evidence/types/{evidence_type}"
    API_EVIDENCE_UPLOAD = "/api/evidence/upload"
    API_EVIDENCE_EVIDENCE_ID = "/api/evidence/{evidence_id}"
    API_JOBS_ = "/api/jobs/"
    API_LOGS_QUERY = "/api/logs/{query}"
    API_REQUEST_ = "/api/request/"
    API_REQUEST_SUMMARY = "/api/request/summary"
    API_REQUEST_REQUEST_ID = "/api/request/{request_id}"
    API_RESULT_REQUEST_REQUEST_ID = "/api/result/request/{request_id}"
    API_RESULT_TASK_TASK_ID = "/api/result/task/{task_id}"
    API_TASK_STATISTICS = "/api/task/statistics"
    API_TASK_WORKERS = "/api/task/workers"
    API_TASK_TASK_ID = "/api/task/{task_id}"
