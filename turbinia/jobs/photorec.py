from __future__ import unicode_literals
from turbinia.evidence import RawDisk
from turbinia.jobs import interface
from turbinia.jobs import manager
from turbinia.evidence import PhotorecOutput
from turbinia.workers.photorec import PhotorecTask


class PhotorecJob(interface.TurbiniaJob):

  evidence_input = [RawDisk]
  evidence_output = [PhotorecOutput]

  NAME = 'PhotorecJob'

  def create_tasks(self, evidence):
    """Create task for Plaso.

    Args:
      evidence: List of evidence objects to process

    Returns:
        A list of PlasoTasks.
    """
    return [PhotorecTask() for _ in evidence]


manager.JobsManager.RegisterJob(PhotorecJob)