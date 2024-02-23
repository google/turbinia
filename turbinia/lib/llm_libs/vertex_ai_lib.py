"""Turbinia LLM library that uses VertexAI APIs."""

from __future__ import unicode_literals

import logging

import google.generativeai as genai
from turbinia import config as turbinia_config
from turbinia.lib.llm_libs import llm_lib_base

MODEL_NAME = "gemini-1.0-pro"
MAX_OUTOUT_TOKEN = 2048
MODEL_TEMPRATURE = 0.2
# GCP_GENERATIVE_LANGUAGE_API_KEY must be defined in turbinia_config
GENERATIVE_CONFIG = {
    "temperature": MODEL_TEMPRATURE,
    "max_output_tokens": MAX_OUTOUT_TOKEN,
}
SAFETY_SETTINGS = [
    {
        "category": "HARM_CATEGORY_DANGEROUS",
        "threshold": "BLOCK_NONE",
    },
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


class TurbiniaVertexAILib(llm_lib_base.TurbiniaLLMLibBase):
  """Turbinia LLM library that uses VertexAI APIs."""

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
    if turbinia_config.toDict.get('GCP_GENERATIVE_LANGUAGE_API_KEY', None):
      log.warning(
          "GCP_GENERATIVE_LANGUAGE_API_KEY config is not set, "
          "will not call VertexAI APIs, LLM results will be empty.")
      return ("Error while calling VertexAI: "
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
    try:
      response = chat.send_message(prompt_text)
    except genai.types.generation_types.StopCandidateException as e:
      return f"Exception while calling VertexAI: {e}", chat
    text_response = ",".join([
        part.text
        for part in response.candidates[0].content.parts
        if response.candidates[0].content.parts
    ])
    return (text_response, chat)
