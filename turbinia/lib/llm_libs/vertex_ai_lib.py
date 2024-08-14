"""Turbinia LLM library that uses VertexAI APIs."""

import logging

import backoff
from google.api_core import exceptions
import google.generativeai as genai
import ratelimit
from turbinia import config as turbinia_config
from turbinia.lib.llm_libs import llm_lib_base

CALL_LIMIT = 20  # Number of calls to allow within a period
ONE_MINUTE = 60  # One minute in seconds
TEN_MINUTE = 10 * ONE_MINUTE
MODEL_NAME = "gemini-1.5-pro"
MAX_OUTOUT_TOKEN = 8192
MODEL_TEMPRATURE = 0.2
# GCP_GENERATIVE_LANGUAGE_API_KEY must be defined in turbinia_config
GENERATIVE_CONFIG = {
    "temperature": MODEL_TEMPRATURE,
    "max_output_tokens": MAX_OUTOUT_TOKEN,
}
SAFETY_SETTINGS = [
    {
        "category": "HARM_CATEGORY_HARASSMENT",
        "threshold": "BLOCK_NONE",
    },
    {
        "category": "HARM_CATEGORY_HATE_SPEECH",
        "threshold": "BLOCK_NONE",
    },
    {
        "category": "HARM_CATEGORY_SEXUALLY_EXPLICIT",
        "threshold": "BLOCK_NONE",
    },
    {
        "category": "HARM_CATEGORY_DANGEROUS_CONTENT",
        "threshold": "BLOCK_NONE",
    },
]
log = logging.getLogger("turbinia")


def backoff_hdlr(details):
  """Backoff handler for VertexAI calls."""
  log.info(
      "Backing off %s seconds after %s tries", details["wait"],
      details["tries"])


class TurbiniaVertexAILib(llm_lib_base.TurbiniaLLMLibBase):
  """Turbinia LLM library that uses VertexAI APIs."""

  # Retry with exponential backoff strategy when exceptions occur
  @backoff.on_exception(
      backoff.expo,
      (
          exceptions.ResourceExhausted,
          exceptions.ServiceUnavailable,
          exceptions.GoogleAPIError,
          exceptions.InternalServerError,
          exceptions.Cancelled,
          ratelimit.RateLimitException,
      ),  # Exceptions to retry on
      max_time=TEN_MINUTE,
      on_backoff=backoff_hdlr,  # Function to call when retrying
  )
  # Limit the number of calls to the model per minute
  @ratelimit.limits(calls=CALL_LIMIT, period=ONE_MINUTE)
  def prompt_with_history(
      self, prompt_text: str, history_session: genai.ChatSession = None) -> str:
    """Sends a prompt to the Gemini-pro model using VertexAI.

    Args:
        prompt_text: The text of the prompt.
        history_session: optional conversation history if it is desired to keep
          the state of the conversation, i.e. a chat.

    Returns:
        A tuple of the response from the Gemini-pro model and a history session.
    """
    log.info('Calling VertexAI using generative model "%s"', MODEL_NAME)
    if not turbinia_config.GCP_GENERATIVE_LANGUAGE_API_KEY:
      log.error(
          "GCP_GENERATIVE_LANGUAGE_API_KEY config is not set, "
          "will not call VertexAI APIs, LLM results will be empty.")
      return (
          "Error while calling VertexAI: "
          "GCP_GENERATIVE_LANGUAGE_API_KEY is not set"), None
    genai.configure(api_key=turbinia_config.GCP_GENERATIVE_LANGUAGE_API_KEY)
    chat = history_session
    if not chat:
      model = genai.GenerativeModel(
          model_name=f"models/{MODEL_NAME}",
          generation_config=GENERATIVE_CONFIG,
          safety_settings=SAFETY_SETTINGS,
      )
      chat = model.start_chat()
    else:
      # Since this is a multi-turn conversation, the history is sent with each
      # new request, the model's reply sent in the history with the next message
      # can't be empty else the proto validators will complain behind the scene.
      # However in some cases the model sends an empty content, we patch it and
      # replace it with an ack message to avoid erroring out when re-sending the
      # empty content in hostory with the next message.
      history = chat.history
      history_patched = []
      for content in history:
        if not content.parts:
          content.parts = [genai.types.content_types.to_part("ack")]
        history_patched.append(content)
      chat.history = history_patched
    try:
      response = chat.send_message(prompt_text)
    except genai.types.generation_types.StopCandidateException as e:
      return f"VertexAI LLM response was stopped because of: {e}", chat
    except Exception as e:
      log.warning("Exception while calling VertexAI: %s", e)
      raise
    text_response = ",".join(
        [part.text for part in response.candidates[0].content.parts])
    return (text_response, chat)
