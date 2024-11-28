"""Job to execute elf analysis task."""

from turbinia.evidence import ElfExtraction
from turbinia.evidence import Directory
from turbinia.evidence import RawDisk
from turbinia.evidence import ReportText
from turbinia.jobs import interface
from turbinia.jobs import manager
from turbinia.workers.analysis import elf


class ElfAnalysisJob(interface.TurbiniaJob):
  """ELF analysis job."""

  evidence_input = [ElfExtraction]
  evidence_output = [ReportText]

  NAME = 'ElfAnalysisJob'

  def create_tasks(self, evidence):
    """Create task.
    Args:
      evidence: List of evidence objects to process
    Returns:
        A list of tasks to schedule.
    """
    tasks = [elf.ElfAnalysisTask() for _ in evidence]
    return tasks


manager.JobsManager.RegisterJob(ElfAnalysisJob)
