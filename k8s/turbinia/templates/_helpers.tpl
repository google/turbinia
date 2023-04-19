{{/*
Expand the name of the chart.
*/}}
{{- define "turbinia.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "turbinia.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "turbinia.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "turbinia.labels" -}}
helm.sh/chart: {{ include "turbinia.chart" . }}
{{ include "turbinia.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
date: {{ now | htmlDate }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "turbinia.selectorLabels" -}}
app.kubernetes.io/name: {{ include "turbinia.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "turbinia.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "turbinia.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Create persistence volume claim name.
*/}}
{{- define "turbinia.pvc.name" -}}
{{- printf "%s-%s" .Values.persistence.name "claim" }}
{{- end }}

{{/*
GCP Project ID validation
*/}}
{{- define "turbinia.gcp.project" -}}
{{- if .Values.gcp.projectID -}}
{{- printf "%s" .Values.gcp.projectID -}}
{{- else -}}
{{ fail "A valid .Values.gcp.projectID entry is required!" }}
{{- end -}}
{{- end -}}

{{/*
GCP Project region validation
*/}}
{{- define "turbinia.gcp.region" -}}
{{- if .Values.gcp.projectRegion -}}
{{- printf "%s" .Values.gcp.projectRegion -}}
{{- else -}}
{{ fail "A valid .Values.gcp.projectRegion entry is required!" }}
{{- end -}}
{{- end -}}

{{/*
GCP Project zone validation
*/}}
{{- define "turbinia.gcp.zone" -}}
{{- if .Values.gcp.projectZone -}}
{{- printf "%s" .Values.gcp.projectZone -}}
{{- else -}}
{{ fail "A valid .Values.gcp.projectZone entry is required!" }}
{{- end -}}
{{- end -}}

{{/*
Redis subcharts connection url
*/}}
{{- define "turbinia.redis.url" -}}
{{- if .Values.redis.enabled -}}
{{- $name := include "common.names.fullname" (dict "Chart" (dict "Name" "redis") "Release" .Release "Values" .Values.redis) -}}
{{- $port := .Values.redis.master.service.ports.redis -}}
{{- if .Values.redis.auth.enabled -}}
{{- printf "redis://default:'$REDIS_PASSWORD'@%s-master:%.0f" $name $port -}}
{{- else -}}
{{- printf "redis://%s-master:%.0f" $name $port -}}
{{- end -}}
{{- else -}}
{{ fail "Attempting to use Redis, but the subchart is not enabled. This will lead to misconfiguration" }}
{{- end -}}
{{- end -}}