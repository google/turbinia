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
"""Tests for the Tomcat analysis task."""

from __future__ import unicode_literals

import unittest

from turbinia import config
from turbinia.workers import tomcat


class TomcatAnalysisTaskTest(unittest.TestCase):
  """Test for the Tomcat Task."""

  TOMCAT_PASSWORD_FILE = """<?xml version='1.0' encoding='utf-8'?>
<tomcat-users>
    <role rolename="tomcat"/>
    <role rolename="role1"/>
    <user username="tomcat" password="tomcat" roles="tomcat"/>
    <user username="both" password="tomcat" roles="tomcat,role1"/>
</tomcat-users>"""

  # pylint: disable=line-too-long
  TOMCAT_PASSWORD_FILE_REPORT = """#### **Tomcat analysis found 2 results**
* Tomcat user: <user username="tomcat" password="tomcat" roles="tomcat"/>
* Tomcat user: <user username="both" password="tomcat" roles="tomcat,role1"/>"""

  TOMCAT_PASSWORD_FILE_REPORT_SUMMARY = 'Tomcat analysis found 2 results'

  # pylint: disable=line-too-long
  TOMCAT_APP_DEPLOY_LOG = r"""21-Mar-2017 19:21:08.140 INFO [localhost-startStop-2] org.apache.catalina.startup.HostConfig.deployWAR Deploying web application archive C:\Program Files\Apache Software Foundation\Tomcat 9.0\webapps\MyAwesomeApp.war
10-Sep-2012 11:41:12.283 INFO [localhost-startStop-1] org.apache.catalina.startup.HostConfig.deployWAR Deploying web application archive /opt/apache-tomcat-8.0.32/webapps/badboy.war"""

  # pylint: disable=line-too-long
  TOMCAT_APP_DEPLOY_LOG_REPORT = r"""#### **Tomcat analysis found 2 results**
* Tomcat App Deployed: 21-Mar-2017 19:21:08.140 INFO [localhost-startStop-2] org.apache.catalina.startup.HostConfig.deployWAR Deploying web application archive C:\Program Files\Apache Software Foundation\Tomcat 9.0\webapps\MyAwesomeApp.war
* Tomcat App Deployed: 10-Sep-2012 11:41:12.283 INFO [localhost-startStop-1] org.apache.catalina.startup.HostConfig.deployWAR Deploying web application archive /opt/apache-tomcat-8.0.32/webapps/badboy.war"""

  # pylint: disable=line-too-long
  TOMCAT_ACCESS_LOG = """1.2.3.4 - - [12/Apr/2018:14:01:08 -0100] "GET /manager/html HTTP/1.1" 401 2001
1.2.3.4 - admin [12/Apr/2018:14:01:09 -0100] "GET /manager/html HTTP/1.1" 200 22130
1.2.3.4 - admin [12/Apr/2018:14:01:39 -0100] "POST /manager/html/upload?org.apache.catalina.filters.CSRF_NONCE=1ABCDEFGKLMONPQRSTIRQKD240384739 HTTP/1.1" 200 27809"""

  # pylint: disable=line-too-long
  TOMCAT_ACCESS_LOG_REPORT = """#### **Tomcat analysis found 1 results**
* Tomcat Management: 1.2.3.4 - admin [12/Apr/2018:14:01:39 -0100] "POST /manager/html/upload?org.apache.catalina.filters.CSRF_NONCE=1ABCDEFGKLMONPQRSTIRQKD240384739 HTTP/1.1" 200 27809"""

  def test_analyse_tomcat_file(self):
    """Tests the analyze_tomcat_file method."""
    config.LoadConfig()
    task = tomcat.TomcatAnalysisTask()

    (report, priority, summary) = task.analyse_tomcat_file(
        self.TOMCAT_PASSWORD_FILE)
    self.assertEqual(report, self.TOMCAT_PASSWORD_FILE_REPORT)
    self.assertEqual(priority, 20)
    self.assertEqual(summary, self.TOMCAT_PASSWORD_FILE_REPORT_SUMMARY)

    report = task.analyse_tomcat_file(self.TOMCAT_APP_DEPLOY_LOG)[0]
    self.assertEqual(report, self.TOMCAT_APP_DEPLOY_LOG_REPORT)

    report = task.analyse_tomcat_file(self.TOMCAT_ACCESS_LOG)[0]
    self.assertEqual(report, self.TOMCAT_ACCESS_LOG_REPORT)


if __name__ == '__main__':
  unittest.main()
