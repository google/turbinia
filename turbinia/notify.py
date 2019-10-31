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


import logging
from turbinia import config
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import smtplib
log=logging.getLogger('turbinia')

#Sends notfications via email
def sendmail(message):
    '''Sends an Email notification via SMTP'''
    try:
        if config.EMAIL_NOTIFICATIONS == True:

            #Puts message in MIME format
            msg = MIMEMultipart()
            msg['From'] = config.EMAIL_ADDRESS
            msg['To'] = config.EMAIL_RECIEVING_ADDRESS
            msg['Subject'] = config.EMAIL_SUBJECT
            msg.attach(MIMEText(message))

            #start SMTP
            server = smtplib.SMTP(config.EMAIL_HOST_ADDRESS,config.EMAIL_PORT)

            # identify to mail server
            server.ehlo()

            # secure email using TLS
            server.starttls()

            # reidentify as using TLS
            server.ehlo()

            #Attempt to login
            try:
                server.login(config.EMAIL_ADDRESS, config.EMAIL_PASSWORD)
            except NameError:
                log.info('EMAIL_ADDRESS or EMAIL_PASSWORD is not definied, attempting to continue without logging in')

            server.sendmail(config.EMAIL_ADDRESS, config.EMAIL_RECIEVING_ADDRESS,msg.as_string())

            #terminate connection
            server.quit()
            log.info('Email notification sent')
        else:
            log.info('Email notifications are disabled')
    except Exception as e:
            log.error(e)
            log.info('Email failed to send, check config')

def main(message):
    sendmail(message)
