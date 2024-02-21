"""Library to call LLM APIs."""

from __future__ import unicode_literals

from turbinia import config as turbinia_config
from turbinia.lib.llm_libs import vertex_ai_lib

PROVIDERS_MAP = {"vertexai": vertex_ai_lib.TurbiniaVertexAILib}


class TurbiniaLLMClient(PROVIDERS_MAP.get(turbinia_config.LLM_PROVIDER)):
  """Library to call LLM APIs."""
  pass
