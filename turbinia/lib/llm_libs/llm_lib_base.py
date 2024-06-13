"""Base class for Turbinia LLM libraries."""

import abc
import typing


class TurbiniaLLMLibBase(metaclass=abc.ABCMeta):
  """Base class for Turbinia LLM libraries."""

  @abc.abstractmethod
  def prompt_with_history(
      self, prompt_text: str, history_session: typing.Any = None) -> str:
    """Sends a prompt to an LLM API and returns the response.

    Args:
        prompt_text: The text of the prompt.
        history_session: optional conversation history if it is desired to keep
          the state of the conversation, i.e. a chat.

    Returns:
        A tuple of the response from the model and a history session.
    """
