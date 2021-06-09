# -*- coding: utf-8 -*-
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
"""Sends email notifications"""

import logging
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from turbinia import config

log = logging.getLogger('turbinia')


#Sends notifications via email
def sendmail(address, subject, message):
  """Sends an Email notification via SMTP
     Args:
         address: This is the address that the email will be sent to
         subject: This will be the subject of the email
         message: This will be the message of the email
  """
  try:
    if config.EMAIL_NOTIFICATIONS is True:

      #Puts message in MIME format
      msg = MIMEMultipart()
      msg['From'] = config.EMAIL_ADDRESS
      msg['To'] = address
      msg['Subject'] = subject
      msg.attach(MIMEText(message))

      #start SMTP
      server = smtplib.SMTP(config.EMAIL_HOST_ADDRESS, config.EMAIL_PORT)

      # identify to mail server
      server.ehlo()

      # secure email using TLS
      server.starttls()

      # reidentify as using TLS
      server.ehlo()

      #Attempt to login
      if config.EMAIL_PASSWORD != '':
        server.login(config.EMAIL_ADDRESS, config.EMAIL_PASSWORD)

      else:
        log.info(
            'Email password is blank, '
            'attempting to continue without logging in')

      server.sendmail(config.EMAIL_ADDRESS, address, msg.as_string())
      log.info('Email notification sent to ' + address)
    else:
      log.info('Email notifications are disabled')

  except smtplib.SMTPException as e:
    log.error(e)
    log.error(
        'Email failed to send, SMTP has raised an error,'
        ' this likely means that there is a problem with the config')
  except TypeError:
    log.error('Email failed to send, there is likely a problem with the config')
  except NameError:
    log.error(
        'Email failed to send, A value which is required'
        ' for email notifications is not defined in the config')

  finally:
    #Terminate connection to server if active
    try:
      server.quit()
    except UnboundLocalError:
      pass
