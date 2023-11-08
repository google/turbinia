# do not import all endpoints into this module because that uses a lot of memory and stack frames
# if you need the ability to import all endpoints from this module, import them with
# from turbinia_api_lib.apis.tag_to_api import tag_to_api

import enum


class TagValues(str, enum.Enum):
    TURBINIA_CONFIGURATION = "Turbinia Configuration"
    TURBINIA_EVIDENCE = "Turbinia Evidence"
    TURBINIA_JOBS = "Turbinia Jobs"
    TURBINIA_LOGS = "Turbinia Logs"
    TURBINIA_REQUEST_RESULTS = "Turbinia Request Results"
    TURBINIA_REQUESTS = "Turbinia Requests"
    TURBINIA_TASKS = "Turbinia Tasks"
