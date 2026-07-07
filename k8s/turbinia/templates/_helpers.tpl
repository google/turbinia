{{/*
Expand the name of the chart.
*/}}
{{- define "turbinia.name" -}}
{{- default .Chart.Name | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "turbinia.fullname" -}}
{{- if contains .Chart.Name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name "turbinia" | trunc 63 | trimSuffix "-" }}
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
date: "{{ now | htmlDate }}"
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
Return the proper persistence volume claim name
*/}}
{{- define "turbinia.pvc.name" -}}
{{- $pvcName := .Values.persistence.name -}}
{{- if and .Values.global .Values.global.existingPVC -}}
{{- printf "%s-%s" .Values.global.existingPVC "claim" }}
{{- else -}}
{{- printf "%s-%s-claim" .Release.Name $pvcName }}
{{- end -}}
{{- end -}}

{{/*
Return the proper Storage Class
*/}}
{{- define "turbinia.storage.class" -}}
{{- $storageClass := .Values.persistence.storageClass -}}
{{- if .Values.global -}}
    {{- if .Values.global.storageClass -}}
        {{- $storageClass = .Values.global.storageClass -}}
    {{- end -}}
{{- end -}}
{{- if $storageClass -}}
  {{- if (eq "-" $storageClass) -}}
      {{- printf "storageClassName: \"\"" -}}
  {{- else }}
      {{- printf "storageClassName: %s" $storageClass -}}
  {{- end -}}
{{- end -}}
{{- end -}}

{{/*
GCP Project ID validation
*/}}
{{- define "turbinia.gcp.project" -}}
{{- if and .Values.gcp.projectID .Values.gcp.enabled -}}
{{- printf "%s" .Values.gcp.projectID -}}
{{- else -}}
{{ fail "A valid .Values.gcp.projectID entry is required!" }}
{{- end -}}
{{- end -}}

{{/*
GCP Project region validation
*/}}
{{- define "turbinia.gcp.region" -}}
{{- if and .Values.gcp.projectRegion .Values.gcp.enabled -}}
{{- printf "%s" .Values.gcp.projectRegion -}}
{{- else -}}
{{ fail "A valid .Values.gcp.projectRegion entry is required!" }}
{{- end -}}
{{- end -}}

{{/*
GCP Project zone validation
*/}}
{{- define "turbinia.gcp.zone" -}}
{{- if and .Values.gcp.projectZone .Values.gcp.enabled -}}
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

{{/*
Redis subcharts host url
*/}}
{{- define "turbinia.redis.url.noport" -}}
{{- if .Values.redis.enabled -}}
{{- $name := include "common.names.fullname" (dict "Chart" (dict "Name" "redis") "Release" .Release "Values" .Values.redis) -}}
{{- if .Values.redis.auth.enabled -}}
{{- printf "%s-master" $name -}}
{{- else -}}
{{- printf "%s-master" $name -}}
{{- end -}}
{{- else -}}
{{ fail "Attempting to use Redis, but the subchart is not enabled. This will lead to misconfiguration" }}
{{- end -}}
{{- end -}}

{{/*
Turbinia service port
*/}}
{{- define "turbinia.service.port" -}}
{{- if .Values.global.turbinia.servicePort -}}
{{ .Values.global.turbinia.servicePort }}
{{- else -}}
{{ .Values.service.port }}
{{- end -}}
{{- end -}}

{{/*
Turbinia config map
*/}}
{{- define "turbinia.configmap" -}}
{{- if .Values.config.existingConfigMap -}}
{{ .Values.config.existingConfigMap }}
{{- else -}}
{{ include "turbinia.fullname" . }}-configmap
{{- end -}}
{{- end -}}