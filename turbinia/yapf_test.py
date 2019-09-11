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
    try:
      subprocess.check_output(
          ['yapf', '--style', config_path, '--diff', '-r', turbinia_path])
    except subprocess.CalledProcessError as e:
      if hasattr(e, 'output'):
        raise Exception(
            'From the root directory of the repository, run '
            '"yapf --style {0:s} -i -r {1:s}" to correct '
            'these problems: {2:s}'.format(
                config_path, turbinia_path, e.output.encode('utf-8')))
      raise


if __name__ == '__main__':
  unittest.main()
