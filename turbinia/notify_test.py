# -*- coding: utf-8 -*-
# Copyright 2016 Google Inc.
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
"""Tests for Turbinia Notifier code."""

import unittest
from smtplib import SMTPException
from unittest.mock import patch
from turbinia import config
from turbinia import notify


class TestSendmail(unittest.TestCase):
  """Test Notifier module."""

  def setUp(self):
    self.config = config
    self.config.EMAIL_NOTIFICATIONS = True
    self.config.EMAIL_ADDRESS = 'test@example.com'
    self.config.EMAIL_HOST_ADDRESS = 'smtp.gmail.com'
    self.config.EMAIL_PORT = 587
    self.config.EMAIL_PASSWORD = 'testpassword'

  @patch('smtplib.SMTP', autospec=True)
  @patch('turbinia.config')
  def test_sendmail(self, mock_config, mock_smtp):
    mock_config.return_value = self.config

    # Test that email is sent when all values are defined
    notify.sendmail('test@example.com', 'Test Subject', 'Test Message')
    mock_smtp.assert_called_once()
    mock_smtp().starttls.assert_called_once()
    mock_smtp().login.assert_called_once()
    mock_smtp().ehlo.assert_called()
    mock_smtp().sendmail.assert_called_once()

    # Test that email is not sent when EMAIL_NOTIFICATIONS is False
    mock_smtp.reset_mock()
    self.config.EMAIL_NOTIFICATIONS = False
    notify.sendmail('test@example.com', 'Test Subject', 'Test Message')
    mock_smtp().sendmail.assert_not_called()
    self.config.EMAIL_NOTIFICATIONS = True

    # Test that email is not sent when EMAIL_PASSWORD is not defined
    mock_smtp.reset_mock()
    self.config.EMAIL_PASSWORD = ''
    with self.assertLogs('turbinia', level='INFO') as turbinia_info_log:
      notify.sendmail('test@example.com', 'Test Subject', 'Test Message')
      self.assertEqual(
          turbinia_info_log.output[0],
          'INFO:turbinia.notify:Email password is blank, attempting to continue '
          'without logging in')
      mock_smtp.assert_called_once()
    self.config.EMAIL_PASSWORD = 'testpassword'

    # Test that email is not sent when SMTP raises an exception
    mock_smtp.reset_mock()
    mock_smtp.side_effect = SMTPException()
    with self.assertLogs('turbinia', level='ERROR') as turbinia_error_log:
      try:
        notify.sendmail('test@example.com', 'Test Subject', 'Test Message')
      except Exception:
        pass
      self.assertEqual(
          turbinia_error_log.output[1],
          'ERROR:turbinia.notify:Email failed to send, SMTP has raised an error, '
          'this likely means that there is a problem with the config')

    # Test that email is not sent when SMTP raises a TypeError
    mock_smtp.side_effect = TypeError()
    with self.assertLogs('turbinia', level='ERROR') as turbinia_error_log:
      try:
        notify.sendmail('test@example.com', 'Test Subject', 'Test Message')
      except Exception:
        pass
      self.assertEqual(
          turbinia_error_log.output[0],
          'ERROR:turbinia.notify:Email failed to send, there is likely a problem '
          'with the config')

    # Test that email is not sent when SMTP raises a NameError
    mock_smtp.reset_mock()
    mock_smtp.side_effect = NameError()
    with self.assertLogs('turbinia', level='INFO') as turbinia_info_log:
      try:
        notify.sendmail('test@example.com', 'Test Subject', 'Test Message')
      except Exception:
        pass
      self.assertEqual(
          turbinia_info_log.output[0],
          'ERROR:turbinia.notify:Email failed to send, A value which is required '
          'for email notifications is not defined in the config')
