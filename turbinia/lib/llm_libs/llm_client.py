"""Library to call LLM APIs."""

from turbinia import config as turbinia_config
from turbinia.lib.llm_libs import vertex_ai_lib

# Please extend the PROVIDERS_MAP to add further providers. Each
# dict item has key equivalent to a provider name, and a reference
# to a class that implements TurbiniaLLMLibBase. The LLM_PROVIDER
# value in config must be one of the keys below.
PROVIDERS_MAP = {"vertexai": vertex_ai_lib.TurbiniaVertexAILib}


class TurbiniaLLMClient(PROVIDERS_MAP.get(turbinia_config.LLM_PROVIDER,
                                          object)):
  """Library to call LLM APIs.

  The library inherets the implementation class for the `LLM_PROVIDER` in
  configs. If no provider specified, the basic `object` type will be used
  to fail gracefully.
  """

  pass
