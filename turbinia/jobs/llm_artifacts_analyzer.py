"""Job to execute LLM analysis on log, config and history files."""

from __future__ import unicode_literals

from turbinia import evidence as evidence_module
from turbinia import jobs
from turbinia import workers
from turbinia.workers.analysis import llm_analyzer as llm_analyzer_module

LLM_ARTIFACTS = [
    'BashShellConfigurationFile',
    'BashShellHistoryFile',
    'BashShellSessionFile',
    'BourneShellHistoryFile',
    'CShellConfigurationFile',
    'FishShellConfigurationFile',
    'FishShellHistoryFile',
    'KornShellConfigurationFile',
    'RootUserShellConfigs',
    'RootUserShellHistory',
    'ShellConfigurationFile',
    'ShellHistoryFile',
    'ShellLogoutFile',
    'ShellProfileFile',
    'TeeShellConfigurationFile',
    'ZShellConfigurationFile',
    'ZShellHistoryFile',
    'JupyterConfigFile',
    'NfsExportsFile',
    'RedisConfigFile',
    'DNSResolvConfFile',
    'SambaConfigFile',
    'SshdConfigFile',
    'SshUserConfigFile',
    'GKEDockerContainerLogs',
    'DockerContainerConfig',
    'NginxAccessLogs',
    'ApacheAccessLogs',
    'WordpressConfigFile',
    'MicrosoftIISLogs',
    'ElasticsearchAccessLog',
    'ElasticsearchAuditLog',
    'ElasticsearchGCLog',
    'ElasticsearchLogs',
    'ElasticsearchServerLog',
    'MongoDBConfigurationFile',
    'MongoDBDatabasePath',
    'MongoDBLogFiles',
    'MySQLConfigurationFiles',
    'MySQLDataDictionary',
    'MySQLDataDirectory',
    'MySQLLogFiles',
    'OpenSearchLogFiles',
    'PostgreSQLConfigurationFiles',
    'PostgreSQLDataDirectory',
    'PostgreSQLLogFiles',
    'RedisConfigurationFile',
    'RedisDataDirectory',
    'RedisLogFiles',
]


class LLMArtifactsExtractionJob(jobs.TurbiniaJob):
  """LLM artifacts extraction job."""

  evidence_input = [
      evidence_module.ContainerdContainer,
      evidence_module.Directory,
      evidence_module.CompressedDirectory,
      evidence_module.DockerContainer,
      evidence_module.EwfDisk,
      evidence_module.GoogleCloudDisk,
      evidence_module.GoogleCloudDiskRawEmbedded,
      evidence_module.RawDisk,
  ]
  evidence_output = [evidence_module.ExportedFileArtifact]

  NAME = 'LLMArtifactsExtractionJob'

  def create_tasks(self, evidence):
    """Create task.

    Args:
      evidence: List of evidence objects to process

    Returns:
        A list of tasks to schedule.
    """
    tasks = []
    for artifact_name in LLM_ARTIFACTS:
      tasks.extend([
          workers.artifact.FileArtifactExtractionTask(artifact_name)
          for _ in evidence
      ])
    return tasks


class LLMAnalysisJob(jobs.TurbiniaJob):
  """LLM analysis job for selected history, logs and config files."""

  evidence_input = [evidence_module.ExportedFileArtifact]
  evidence_output = [evidence_module.ReportText]

  NAME = 'LLMAnalysisJob'

  def create_tasks(self, evidence):
    """Create task.

    Args:
      evidence: List of evidence objects to process

    Returns:
        A list of tasks to schedule.
    """
    evidence = [e for e in evidence if e.artifact_name in LLM_ARTIFACTS]
    return [llm_analyzer_module.LLMAnalyzerTask() for _ in evidence]


jobs.manager.JobsManager.RegisterJobs(
    [LLMArtifactsExtractionJob, LLMAnalysisJob])
