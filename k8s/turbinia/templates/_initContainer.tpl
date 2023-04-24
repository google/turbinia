{{/*
Init Container for when a Turbinia pod starts. To prevent duplicate code,
this file has been created which then applies to both the Turbinia Server, API,
and Worker pod upon startup.
*/}}
{{- define "turbinia.initContainer" -}}
{{- $userconfigs := .Files.Get .Values.config.override -}}
- name: init-turbinia
  image: busybox
  command: ['sh', '-c', '/init/init-turbinia.sh']
  env:
    {{- if and .Values.redis.enabled .Values.redis.auth.enabled }}
    - name: REDIS_PASSWORD
      valueFrom:
        # Referencing from charts/redis/templates/_helpers.tpl
        secretKeyRef:
          name: {{ include "redis.secretName" .Subcharts.redis }}
          key: {{ include "redis.secretPasswordKey" .Subcharts.redis }}
    {{- end }}
  volumeMounts:
    - mountPath: /mnt/turbiniavolume
      name: turbiniavolume
    - mountPath: /init
      name: init-turbinia
    - mountPath: /etc/turbinia
      name: turbinia-configs
    {{- if $userconfigs }}
    - mountPath: /tmp/turbinia
      name: user-configs
    {{- end }}
{{- end }}
