"""Job to execute macho analysis task."""

from turbinia.evidence import MachoExtraction
from turbinia.evidence import Directory
from turbinia.evidence import RawDisk
from turbinia.evidence import ReportText
from turbinia.jobs import interface
from turbinia.jobs import manager
from turbinia.workers.analysis import macho


class MachoAnalysisJob(interface.TurbiniaJob):
  """Mach-O analysis job."""

  evidence_input = [MachoExtraction]
  evidence_output = [ReportText]

  NAME = 'MachoAnalysisJob'

  def create_tasks(self, evidence):
    """Create task.
    Args:
      evidence: List of evidence objects to process
    Returns:
        A list of tasks to schedule.
    """
    tasks = [macho.MachoAnalysisTask() for _ in evidence]
    return tasks


manager.JobsManager.RegisterJob(MachoAnalysisJob)
