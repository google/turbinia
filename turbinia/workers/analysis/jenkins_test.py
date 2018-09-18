# -*- coding: utf-8 -*-
# Copyright 2018 Google Inc.
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
"""Tests for the Jenkins analysis task."""

from __future__ import unicode_literals

import unittest

from turbinia import config
from turbinia.workers.analysis import jenkins


class JenkinsAnalysisTaskTest(unittest.TestCase):

  JENKINS_SYSTEM_CONFIG = """<?xml version='1.1' encoding='UTF-8'?>
  <hudson>
    <disabledAdministrativeMonitors/>
    <version>2.121.2</version>
    <installStateName>NEW</installStateName>
    <numExecutors>2</numExecutors>
    <mode>NORMAL</mode>
    <useSecurity>true</useSecurity>
    <authorizationStrategy class="hudson.security.FullControlOnceLoggedInAuthorizationStrategy">
      <denyAnonymousReadAccess>true</denyAnonymousReadAccess>
    </authorizationStrategy>
    <securityRealm class="hudson.security.HudsonPrivateSecurityRealm">
      <disableSignup>true</disableSignup>
      <enableCaptcha>false</enableCaptcha>
    </securityRealm>
    <disableRememberMe>false</disableRememberMe>
    <projectNamingStrategy class="jenkins.model.ProjectNamingStrategy$DefaultProjectNamingStrategy"/>
    <workspaceDir>${JENKINS_HOME}/workspace/${ITEM_FULL_NAME}</workspaceDir>
    <buildsDir>${ITEM_ROOTDIR}/builds</buildsDir>
    <jdks/>
    <viewsTabBar class="hudson.views.DefaultViewsTabBar"/>
    <myViewsTabBar class="hudson.views.DefaultMyViewsTabBar"/>
    <clouds/>
    <scmCheckoutRetryCount>0</scmCheckoutRetryCount>
    <views>
      <hudson.model.AllView>
        <owner class="hudson" reference="../../.."/>
        <name>all</name>
        <filterExecutors>false</filterExecutors>
        <filterQueue>false</filterQueue>
        <properties class="hudson.model.View$PropertyList"/>
      </hudson.model.AllView>
    </views>
    <primaryView>all</primaryView>
    <slaveAgentPort>-1</slaveAgentPort>
    <disabledAgentProtocols>
      <string>JNLP-connect</string>
      <string>JNLP2-connect</string>
    </disabledAgentProtocols>
    <label></label>
    <crumbIssuer class="hudson.security.csrf.DefaultCrumbIssuer">
      <excludeClientIPFromCrumb>false</excludeClientIPFromCrumb>
    </crumbIssuer>
    <nodeProperties/>
    <globalNodeProperties/>
  </hudson>
  """

  JENKINS_USER_CONFIG = """<?xml version='1.1' encoding='UTF-8'?>
  <user>
    <fullName>admin</fullName>
    <properties>
      <jenkins.security.ApiTokenProperty>
        <apiToken>{AQAAABAAAAAw2v+nvot+GLKWtq30DPlsk2lTEST==}</apiToken>
      </jenkins.security.ApiTokenProperty>
      <hudson.model.MyViewsProperty>
        <views>
          <hudson.model.AllView>
            <owner class="hudson.model.MyViewsProperty" reference="../../.."/>
            <name>all</name>
            <filterExecutors>false</filterExecutors>
            <filterQueue>false</filterQueue>
            <properties class="hudson.model.View$PropertyList"/>
          </hudson.model.AllView>
        </views>
      </hudson.model.MyViewsProperty>
      <hudson.model.PaneStatusProperties>
        <collapsed/>
      </hudson.model.PaneStatusProperties>
      <hudson.search.UserSearchProperty>
        <insensitiveSearch>true</insensitiveSearch>
      </hudson.search.UserSearchProperty>
      <hudson.security.HudsonPrivateSecurityRealm_-Details>
        <passwordHash>#jbcrypt:$2a$10$DSltvO4YXZuoLuUU77R871627TEST</passwordHash>
      </hudson.security.HudsonPrivateSecurityRealm_-Details>
    </properties>
  </user>
  """

  EXPECTED_VERSION = '2.121.2'
  EXPECTED_CREDENTIALS = [('admin', '$2a$10$DSltvO4YXZuoLuUU77R871627TEST')]

  def test_extract_jenkins_version(self):
    """Tests the extract_jenkins_version method."""
    config.LoadConfig()
    task = jenkins.JenkinsAnalysisTask()

    version = task._extract_jenkins_version(
      str(self.JENKINS_SYSTEM_CONFIG))

    self.assertEqual(version, self.EXPECTED_VERSION)

  def test_extract_jenkins_credentials(self):
    """Tests the extract_jenkins_credentials method."""
    config.LoadConfig()
    task = jenkins.JenkinsAnalysisTask()

    credentials = task._extract_jenkins_credentials(
      str(self.JENKINS_USER_CONFIG))

    self.assertEqual(credentials, self.EXPECTED_CREDENTIALS)


if __name__ == '__main__':
  unittest.main()
