"""Enforce code style with YAPF."""

import os
import subprocess
import unittest


class StyleTest(unittest.TestCase):
  """Enforce code style requirements."""

  def testCodeStyle(self):
    """Check YAPF style enforcement runs cleanly."""
    turbinia_path = os.path.abspath(os.path.dirname(__file__))
    config_path = os.path.join(turbinia_path, '..', '.style.yapf')
    api_client_path = '*api/client/*'
    cli_tool_setup = '*api/cli/setup.py'
    try:
      subprocess.check_output([
          'yapf', '--exclude', api_client_path, '--exclude', cli_tool_setup,
          '--style', config_path, '--diff', '-r', turbinia_path
      ])
    except subprocess.CalledProcessError as exception:
      if hasattr(exception, 'output'):
        raise Exception(
            'From the root directory of the repository, run '
            '"yapf --style {0:s} -i -r {1:s}" to correct '
            'these problems: {2:s}'.format(
                config_path, turbinia_path, exception.output.decode('utf-8')))
      raise


if __name__ == '__main__':
  unittest.main()
