"""Job to execute LLM analysis on log, config and history files."""

from __future__ import unicode_literals

from turbinia import evidence as evidence_module
from turbinia import workers
from turbinia.jobs import interface
from turbinia.jobs import manager
from turbinia.workers.analysis import llm_analyzer as llm_analyzer_module

LLM_ARTIFACTS = [
    # Keep sorted
    'ApacheAccessLogs',
    'ApacheConfigurationFolder',
    'BashShellConfigurationFile',
    'BashShellHistoryFile',
    'BashShellSessionFile',
    'BourneShellHistoryFile',
    'CShellConfigurationFile',
    'ContainerdConfig',
    'ContainerdLogs',
    'DNSResolvConfFile',
    'DockerContainerConfig',
    'ElasticsearchAccessLog',
    'ElasticsearchAuditLog',
    'ElasticsearchGCLog',
    'ElasticsearchLogs',
    'ElasticsearchServerLog',
    'FishShellConfigurationFile',
    'FishShellHistoryFile',
    'GKEDockerContainerLogs',
    'HadoopAppLogs',
    'HadoopAppRoot',
    'HadoopYarnLogs',
    'JupyterConfigFile',
    'KornShellConfigurationFile',
    'LinuxAuthLogs',
    'LinuxCronLogs',
    'LoginPolicyConfiguration',
    'MicrosoftIISLogs',
    'MongoDBConfigurationFile',
    'MongoDBDatabasePath',
    'MongoDBLogFiles',
    'MySQLConfigurationFiles',
    'MySQLDataDictionary',
    'MySQLDataDirectory',
    'MySQLHistoryFile',
    'MySQLLogFiles',
    'NfsExportsFile',
    'NginxAccessLogs',
    'OpenSearchLogFiles',
    'PostgreSQLConfigurationFiles',
    'PostgreSQLDataDirectory',
    'PostgreSQLHistoryFile',
    'PostgreSQLLogFiles',
    'PythonHistoryFile',
    'RedisConfigFile',
    'RedisConfigurationFile',
    'RedisDataDirectory',
    'RedisLogFiles',
    'RootUserShellConfigs',
    'RootUserShellHistory',
    'SSHAuthorizedKeysFiles',
    'SambaConfigFile',
    'ShellConfigurationFile',
    'ShellHistoryFile',
    'ShellLogoutFile',
    'ShellProfileFile',
    'SshUserConfigFile',
    'SshdConfigFile',
    'TeeShellConfigurationFile',
    'WindowsScheduledTasks',
    'WordpressConfigFile',
    'ZShellConfigurationFile',
    'ZShellHistoryFile',
]


class LLMArtifactsExtractionJob(interface.TurbiniaJob):
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
      # To avoid redundent processing between LLM analyzer and other
      # analyzers using same evidence type. LLM analyzer uses evidence
      # type `ExportedFileArtifactLLM` supported by
      # FileArtifactExtractionTask when llm_artifact=True.
      tasks.extend([
          workers.artifact.FileArtifactExtractionTask(
              artifact_name=artifact_name, llm_artifact=True) for _ in evidence
      ])
    return tasks


class LLMAnalysisJob(interface.TurbiniaJob):
  """LLM analysis job for selected history, logs and config files."""

  # To avoid redundent processing between LLM analyzer and other
  # analyzers using same evidence type. LLM analyzer uses seperate
  # evidence type supported by FileArtifactExtractionTask when
  # llm_artifact=True.
  evidence_input = [evidence_module.ExportedFileArtifactLLM]
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


manager.JobsManager.RegisterJobs([LLMArtifactsExtractionJob, LLMAnalysisJob])
