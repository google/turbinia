#!/usr/bin/env python
#
# Copyright 2017 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Methods for formatting text."""

from __future__ import print_function
from __future__ import unicode_literals


def bold(text):
  """Formats text as bold in Markdown format.

  Args:
    text(string): Text to format

  Return:
    string: Formatted text.
  """
  return '**{0:s}**'.format(text.strip())


def heading1(text):
  """Formats text as heading 1 in Markdown format.

  Args:
    text(string): Text to format

  Return:
    string: Formatted text.
  """
  return '# {0:s}'.format(text.strip())


def heading2(text):
  """Formats text as heading 2 in Markdown format.

  Args:
    text(string): Text to format

  Return:
    string: Formatted text.
  """
  return '## {0:s}'.format(text.strip())


def heading3(text):
  """Formats text as heading 3 in Markdown format.

  Args:
    text(string): Text to format

  Return:
    string: Formatted text.
  """
  return '### {0:s}'.format(text.strip())


def heading4(text):
  """Formats text as heading 4 in Markdown format.

  Args:
    text(string): Text to format

  Return:
    string: Formatted text.
  """
  return '#### {0:s}'.format(text.strip())


def heading5(text):
  """Formats text as heading 5 in Markdown format.

  Args:
    text(string): Text to format

  Return:
    string: Formatted text.
  """
  return '##### {0:s}'.format(text.strip())


def bullet(text, level=1):
  """Formats text as a bullet in Markdown format.

  Args:
    text(string): Text to format

  Return:
    string: Formatted text.
  """
  return '{0:s}* {1:s}'.format('    ' * (level - 1), text.strip())


def code(text):
  """Formats text as code in Markdown format.

  Args:
    text(string): Text to format

  Return:
    string: Formatted text.
  """
  return '`{0:s}`'.format(text.strip())
