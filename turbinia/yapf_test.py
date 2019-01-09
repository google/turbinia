"""Enforce code style with YAPF."""

import subprocess
import unittest


class StyleTest(unittest.TestCase):
  """Enforce code style requirements."""

  def testCodeStyle(self):
    """Check YAPF style enforcement runs cleanly."""
    try:
      subprocess.check_output(
          ['yapf', '--diff', '-r', '.'])
    except subprocess.CalledProcessError as e:
      if hasattr(e, 'output'):
        raise Exception(
            'From the root directory of the repository, run '
            '"yapf --style .style.yapf -i -r turbinia/" to correct '
            'these problems: {0}'.format(e.output))
      raise


if __name__ == '__main__':
  unittest.main()
