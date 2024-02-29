"""Tests for TurbiniaVertexAILib class."""
import unittest
import unittest.mock

import google.generativeai as genai
import mock
import pyglove as pg
from turbinia import config
from turbinia.lib.llm_libs import vertex_ai_lib


class TurbiniaVertexAILibTest(unittest.TestCase):
  """Test for TurbiniaVertexAILib class."""

  @mock.patch("google.generativeai.configure")
  @mock.patch("google.generativeai.GenerativeModel")
  def test_prompt_with_history(self, mock_gen_model, mock_gen_config):
    config.LoadConfig()
    config.GCP_GENERATIVE_LANGUAGE_API_KEY = "fakeGcpApiKey"
    config.LLM_PROVIDER = "vertexai"
    mock_gen_config.side_effect = None
    mock_gen_model.return_value.start_chat.side_effect = None
    chat_instance = unittest.mock.MagicMock()
    mock_gen_model.return_value.start_chat.return_value = chat_instance
    chat_instance.send_message.return_value = make_gen_ai_response(
        "Hello world response")
    prompt_text = "Hello world request"
    lib = vertex_ai_lib.TurbiniaVertexAILib()

    response, _ = lib.prompt_with_history(prompt_text)

    self.assertEqual(response, "Hello world response")


def make_gen_ai_response(text):
  return genai.types.GenerateContentResponse(
      done=True,
      iterator=None,
      chunks=[],
      result=pg.Dict(
          prompt_feedback=pg.Dict(block_reason=None),
          candidates=[
              pg.Dict(content=pg.Dict(parts=[pg.Dict(text=text)]),),
          ],
      ),
  )
