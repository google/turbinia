"""Job to execute LLM analysis on log, config and history files."""

import logging

from turbinia import config as turbinia_config
from turbinia import evidence as evidence_module
from turbinia import workers
from turbinia.jobs import interface
from turbinia.jobs import manager
from turbinia.workers.analysis import llm_analyzer as llm_analyzer_module

log = logging.getLogger(__name__)

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
    'ElasticsearchLogs',
    'ElasticsearchServerLog',
    'FishShellConfigurationFile',
    'FishShellHistoryFile',
    'GKEDockerContainerLogs',
    'HadoopAppLogs',
    'HadoopYarnLogs',
    'JupyterConfigFile',
    'KornShellConfigurationFile',
    'LinuxAuthLogs',
    'LinuxCronLogs',
    'LoginPolicyConfiguration',
    'MicrosoftIISLogs',
    'MongoDBConfigurationFile',
    'MongoDBLogFiles',
    'MySQLConfigurationFiles',
    'MySQLHistoryFile',
    'MySQLLogFiles',
    'NfsExportsFile',
    'NginxAccessLogs',
    'OpenSearchLogFiles',
    'PostgreSQLConfigurationFiles',
    'PostgreSQLHistoryFile',
    'PostgreSQLLogFiles',
    'PythonHistoryFile',
    'RedisConfigFile',
    'RedisConfigurationFile',
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
  evidence_output = [evidence_module.ExportedFileArtifactLLM]

  NAME = 'LLMArtifactsExtractionJob'

  def create_tasks(self, evidence):
    """Create task.

    Args:
      evidence: List of evidence objects to process

    Returns:
        A list of tasks to schedule.
    """
    tasks = []
    # Don't start the artifacts extraction tasks if LLM configs are not set
    if not turbinia_config.LLM_PROVIDER:
      log.error(
          'No LLM_PROVIDER in configs, llm_analyzer tasks will be skipped')
      return tasks
    # VertexAI specific-validation to fail early if required config is not set
    if (turbinia_config.LLM_PROVIDER == 'vertexai' and
        not turbinia_config.GCP_GENERATIVE_LANGUAGE_API_KEY):
      log.error(
          'LLM_PROVIDER used is vertexai while GCP_GENERATIVE_LANGUAGE_API_KEY'
          ' config is not set, llm_analyzer tasks will be skipped.')
      return tasks
    # To avoid redundent processing between LLM analyzer and other
    # analyzers using same evidence type. LLM analyzer uses evidence
    # type `ExportedFileArtifactLLM` supported by
    # FileArtifactExtractionTask when llm_artifacts=True.
    tasks.extend([
        workers.artifact.FileArtifactExtractionTask(
            artifact_names=LLM_ARTIFACTS, llm_artifacts=True) for _ in evidence
    ])
    return tasks


class LLMAnalysisJob(interface.TurbiniaJob):
  """LLM analysis job for selected history, logs and config files."""

  # To avoid redundent processing between LLM analyzer and other
  # analyzers using same evidence type. LLM analyzer uses seperate
  # evidence type supported by FileArtifactExtractionTask when
  # llm_artifacts=True.
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
    return [llm_analyzer_module.LLMAnalyzerTask() for _ in evidence]


manager.JobsManager.RegisterJobs([LLMArtifactsExtractionJob, LLMAnalysisJob])
