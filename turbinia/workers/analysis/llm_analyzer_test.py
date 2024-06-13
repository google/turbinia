"""Test for LLMAnalyzerTask task"""
import unittest
import unittest.mock

import google.generativeai as genai
import mock
import pyglove as pg
from turbinia import config
from turbinia import workers
from turbinia.workers.analysis import llm_analyzer


class LLMAnalyzerTaskTest(unittest.TestCase):
  """Test for LLMAnalyzerTask task"""

  BAD_SUDOERS_FILE = "web_team ALL=(ALL:ALL) NOPASSWD: ALL"
  BAD_CONFIG_REPORT = """
**Finding:**
* **What:** Excessive privileges
* **Why:** This allows group "web team" to issue sudo commands without
having to enter password 
"""
  BAD_CONFIG_SUMMARY = (
      "Insecure Sudoers configuration found. Total misconfigs: 1")
  FINDING_PRIORITY = "CRITICAL"

  @mock.patch("google.generativeai.configure")
  @mock.patch("google.generativeai.GenerativeModel")
  def test_llm_analyze_artifact(self, mock_gen_model, mock_gen_config):
    config.LoadConfig()
    config.LLM_PROVIDER = "vertexai"
    config.GCP_GENERATIVE_LANGUAGE_API_KEY = "fakeGcpApiKey"
    task = llm_analyzer.LLMAnalyzerTask()
    mock_gen_config.side_effect = None
    mock_gen_model.return_value.start_chat.side_effect = None
    chat_instance = unittest.mock.MagicMock()
    mock_gen_model.return_value.start_chat.return_value = chat_instance
    chat_instance.send_message.side_effect = [
        make_gen_ai_response(""),
        make_gen_ai_response(""),
        make_gen_ai_response(self.BAD_CONFIG_REPORT),
        make_gen_ai_response(self.FINDING_PRIORITY),
        make_gen_ai_response(self.BAD_CONFIG_SUMMARY),
    ]

    (report, priority, summary) = task.llm_analyze_artifact(
        self.BAD_SUDOERS_FILE, "sudoers_file")

    chat_instance.send_message.assert_called_with(
        "\nPlease summarize all security findings in a single statement, keep"
        " summary short and don't describe the summary\n")
    self.assertEqual(report, self.BAD_CONFIG_REPORT.rstrip().strip())
    self.assertEqual(priority, workers.Priority.CRITICAL)
    self.assertEqual(summary, self.BAD_CONFIG_SUMMARY)

  def test_split_into_chunks(self):
    text = (
        "This is a very long string that needs to be split into multiple"
        " chunks.")
    max_size = 3
    task = llm_analyzer.LLMAnalyzerTask()
    result = task.split_into_chunks(text, max_size)
    self.assertEqual(
        result,
        [
            "This is a",
            "very long",
            "string that",
            "needs to be",
            "split into",
            "multiple",
            "chunks.",
        ],
    )

  def test_chunk_long_strings_config_file(self):
    words = ["Hello", "World", "This", "is", "a", "verylongstring"]
    max_size = 3
    task = llm_analyzer.LLMAnalyzerTask()
    result = task.chunk_long_strings_config_file(words, max_size)
    self.assertEqual(
        result,
        [
            "Hel",
            "lo",
            "Wor",
            "ld",
            "Thi",
            "s",
            "is",
            "a",
            "ver",
            "ylo",
            "ngs",
            "tri",
            "ng",
        ],
    )


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
