"""Job to execute LLM analysis on log, config and history files."""

from __future__ import unicode_literals

import logging
import os

from turbinia import config as turbinia_config
from turbinia import evidence as evidence_module
from turbinia import workers
from turbinia.jobs import interface
from turbinia.jobs import manager
from turbinia.workers.analysis import llm_analyzer as llm_analyzer_module

log = logging.getLogger('turbinia')
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
    evidence_deduped = []
    job_evidence_paths_ctime = {}
    try:
      # Some artifacts may grab the same files, e.g. RedisConfigurationFile and
      # RedisConfigFile will both grab /etc/redis/redis.conf on a linux host.
      # We can't filter using evidence.source_path as in our case turbinia calls
      # create_tasks on each single evidence, i.e. the incoming list "evidence"
      # has one item. Thus we read all evidence under this evidence folder of
      # this job and only process the first created evidence of redundent
      # evidence files to make sure evidence files are not duplicates.
      source_paths = [e.source_path for e in evidence]
      source_filenames = [os.path.basename(p) for p in source_paths]
      jobs_evidence_dir = os.path.sep.join(
          source_paths[0].split(os.path.sep)[:3])
      for dirpath, _, filenames in os.walk(jobs_evidence_dir):
        for filename in filenames:
          abs_path = os.path.join(dirpath, filename)
          # Ignore adding the current source_paths to job_evidence_paths_ctime
          # and ignore if filename is not matching current evidence filename.
          if abs_path in source_paths or filename not in source_filenames:
            continue
          path = drop_random_path_part(abs_path)
          # always keep the ctime of the first created evidence in case there
          # are duplicates.
          if path not in job_evidence_paths_ctime or os.path.getctime(
              abs_path) < job_evidence_paths_ctime.get(path):
            job_evidence_paths_ctime[path] = os.path.getctime(abs_path)
      for item in evidence:
        path = drop_random_path_part(item.source_path)
        # Add to the list of evidence to process only if it is not already
        # there or if it is there but the ctime of current evidence
        # source_path is smaller, i.e. in case of duplicate artifacts,
        # process the first created one only.
        if path not in job_evidence_paths_ctime or os.path.getctime(
            item.source_path) < job_evidence_paths_ctime[path]:
          evidence_deduped.append(item)
          job_evidence_paths_ctime[path] = os.path.getctime(item.source_path)
    # We log and swallow any exception if deduping fail as its logic relies
    # on file paths written by other tasks which might change, this should not
    # break the LLM job. The side effect of this breaking is having two task
    # results for the same artifact in the report.
    except Exception as e:
      log.warning(
          'Deduping evidence at %s failed with %s',
          [e.source_path for e in evidence], e)
      evidence_deduped = evidence
    return [llm_analyzer_module.LLMAnalyzerTask() for _ in evidence_deduped]


def drop_random_path_part(path):
  """Drop the random part of the path generated by FileArtifactExtractionTask.
  
  The path has a random part generated by each FileArtifactExtractionTask run,
  e.g. /evidence/[TURBINIA_REQUEST_ID]/1775-9253-FileArtifactExtractionTask/export/etc/ssh/sshd_config  # pylint: disable=line-too-long
  We need to remove this part, e.g.
  /evidence/[TURBINIA_REQUEST_ID]/export/etc/ssh/sshd_config and compare the
  paths without it, the part we really care about is starting from first
  "export" directory in the path.

  Args:
    path: The path to drop the random part from.

  Returns:
    The path without the random part.
  """
  path = path.split(os.path.sep)
  for path_part in path:
    if 'FileArtifactExtractionTask' in path_part:
      # drop the first part with FileArtifactExtractionTask and break
      path.remove(path_part)
      break
  return os.path.sep.join(path)


manager.JobsManager.RegisterJobs([LLMArtifactsExtractionJob, LLMAnalysisJob])
