{{/* The chart's name. */}}
{{- define "fictionet.name" -}}
{{- default .Chart.Name .Values.global.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/* The release's full name, as Inspect's agent-env chart makes it. */}}
{{- define "fictionet.fullname" -}}
{{- if .Values.global.fullnameOverride -}}
{{- .Values.global.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.global.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" $name .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/* Labels that select the release's pods. Inspect lists pods by app.kubernetes.io/instance. */}}
{{- define "fictionet.selectorLabels" -}}
app.kubernetes.io/name: {{ include "fictionet.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{/* The `labels` value, one per line. */}}
{{- define "fictionet.labelsFromValues" -}}
{{- range $key, $value := .Values.labels }}
{{ $key }}: {{ quote $value }}
{{- end }}
{{- end -}}

{{/* Labels for every object. */}}
{{- define "fictionet.labels" -}}
{{ include "fictionet.selectorLabels" . }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- include "fictionet.labelsFromValues" . }}
{{- end -}}

{{/*
The arguments of `fictionet attach`, from a merged attach config. Takes a
dict with "attach" (the config) and "service" (the service's name).
*/}}
{{- define "fictionet.attachArgs" -}}
{{- $a := .attach -}}
- attach
- --world
- unix:/run/relay/relay.sock
- --name
- {{ default .service $a.name | quote }}
- --type
- {{ $a.type | quote }}
{{- if ne $a.type "tun" }}
- {{ printf "--listen=127.0.0.1:%s" (include "fictionet.proxyPort" $a) | quote }}
- --token-file=/run/fictionet-token/token
- {{ printf "--ip-addr=%s" (first (splitList "/" (required "attach.ipAddr is required for the proxy types" $a.ipAddr))) | quote }}
- {{ printf "--dns=%s" (required "attach.dns is required for the proxy types" $a.dns) | quote }}
- --ready-file=/run/relay/attach.ready
- {{ printf "--world-wait=%v" (int $a.worldWait) | quote }}
{{- else }}
{{- range list "ip-addr:ipAddr" "gateway:gateway" "dns:dns" "ip-addr-v6:ipAddrV6" "gateway-v6:gatewayV6" "dns-v6:dnsV6" }}
{{- $parts := splitList ":" . }}
{{- $flag := printf "--%s" (first $parts) }}
{{- $value := index $a (last $parts) }}
{{- if $value }}
- {{ printf "%s=%v" $flag $value | quote }}
{{- else }}
- {{ printf "--no-%s" (trimPrefix "--" $flag) | quote }}
{{- end }}
{{- end }}
- {{ printf "--mtu=%v" (int $a.mtu) | quote }}
- --no-resolv-conf
- --ready-file=/run/relay/attach.ready
- {{ printf "--world-wait=%v" (int $a.worldWait) | quote }}
{{- range $a.downLinks }}
{{- if . }}
- {{ printf "--down-link=%s" . | quote }}
{{- end }}
{{- end }}
{{- end }}
{{- range $a.extraArgs }}
- {{ . | quote }}
{{- end }}
{{- end -}}

{{/* The exec probe on attach's ready file. */}}
{{- define "fictionet.readyProbe" -}}
exec:
  command: [/fictionet, ready, /run/relay/attach.ready]
{{- end -}}

{{/* The port a proxy type listens on, from a merged attach config. */}}
{{- define "fictionet.proxyPort" -}}
{{- if .port -}}{{ .port }}{{- else if eq .type "socks5" -}}1080{{- else -}}8080{{- end -}}
{{- end -}}

{{/* The token Secret of one service. Takes a dict with "root" and "service". */}}
{{- define "fictionet.tokenSecret" -}}
{{- printf "%s-%s-token" (include "fictionet.fullname" .root) .service | trunc 253 -}}
{{- end -}}
