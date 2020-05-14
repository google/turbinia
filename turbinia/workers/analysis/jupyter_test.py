# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import unittest

from turbinia import config
from turbinia.workers.analysis import jupyter


class JupyterAnalysisTaskTest(unittest.TestCase):
  """test for the Jupyter notebook analysis task."""

  BAD_JUPYTER_CONFIG = """c.NotebookApp.token = ''
c.NotebookApp.password = ''
c.NotebookApp.open_browser = False
c.NotebookApp.port = 0
c.NotebookApp.allow_origin_pat = '(^https://8080-dot-[0-9]+-dot-devshell\.appspot\.com$)z]*.notebooks.googleusercontent.com)'
c.NotebookApp.allow_remote_access = True
c.NotebookApp.disable_check_xsrf = True
c.NotebookApp.notebook_dir = '/home'
c.NotebookApp.notebook_dir = '/home/jupyter'
c.NotebookApp.allow_root = True
c.NotebookApp.password_required = False
"""

  GOOD_JUPYTER_CONFIG = """c.NotebookApp.token = ''
c.NotebookApp.password = 'au6fsdi7acgyac9ivj0asduva'
c.NotebookApp.open_browser = False
c.NotebookApp.port = 8080
c.NotebookApp.allow_origin_pat = '(^https://8080-dot-[0-9]+-dot-devshell\.appspot\.com$)z]*.notebooks.googleusercontent.com)'
c.NotebookApp.allow_remote_access = False
c.NotebookApp.disable_check_xsrf = False
c.NotebookApp.notebook_dir = '/home'
c.NotebookApp.notebook_dir = '/home/jupyter'
c.NotebookApp.allow_root = False
"""

  BAD_CONFIG_SUMMARY = """Insecure Jupyter Notebook configuration found. Total misconfigs: 5"""

  BAD_CONFIG_REPORT = """#### **Insecure Jupyter Notebook configuration found. Total misconfigs: 5**
* There is no password set for this Jupyter Notebook.
* Remote access is enabled on this Jupyter Notebook.
* XSRF protection is disabled.
* Juypter Notebook allowed to run as root.
* Password is not required to access this Jupyter Notebook."""

  GOOD_CONFIG_REPORT = 'No issues found in Jupyter Notebook  configuration.'

  def test_analyse_jupyter_config(self):
    """Tests the analyze_jupyter_config method."""
    config.LoadConfig()
    task = jupyter.JupyterAnalysisTask()

    (report, priority, summary) = task.analyse_config(self.BAD_JUPYTER_CONFIG)
    self.assertEqual(report, self.BAD_CONFIG_REPORT)
    self.assertEqual(priority, 20)
    self.assertEqual(summary, self.BAD_CONFIG_SUMMARY)

    (report, priority, summary) = task.analyse_config(self.GOOD_JUPYTER_CONFIG)
    self.assertEqual(report, self.GOOD_CONFIG_REPORT)


if __name__ == '__main__':
  unittest.main()
