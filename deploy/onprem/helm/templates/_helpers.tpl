{{/* Name helpers — standard chart boilerplate, kept minimal. */}}

{{- define "vectasec.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "vectasec.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "vectasec.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "vectasec.labels" -}}
helm.sh/chart: {{ include "vectasec.chart" . }}
{{ include "vectasec.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: vectasec
{{- end -}}

{{- define "vectasec.selectorLabels" -}}
app.kubernetes.io/name: {{ include "vectasec.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "vectasec.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "vectasec.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{/* Fully-qualified image ref, honouring an optional registry prefix for mirrored/air-gapped
     registries. */}}
{{- define "vectasec.image" -}}
{{- $reg := .root.Values.image.registry | default "" -}}
{{- if $reg -}}
{{- printf "%s/%s:%s" (trimSuffix "/" $reg) .img.repository .img.tag -}}
{{- else -}}
{{- printf "%s:%s" .img.repository .img.tag -}}
{{- end -}}
{{- end -}}

{{/* Name of the Secret holding DATABASE_URL — the chart-managed one, or yours. */}}
{{- define "vectasec.databaseSecretName" -}}
{{- if .Values.database.existingSecret -}}
{{- .Values.database.existingSecret -}}
{{- else -}}
{{- include "vectasec.fullname" . -}}
{{- end -}}
{{- end -}}

{{- define "vectasec.databaseSecretKey" -}}
{{- if .Values.database.existingSecret -}}
{{- .Values.database.existingSecretKey -}}
{{- else -}}
DATABASE_URL
{{- end -}}
{{- end -}}
