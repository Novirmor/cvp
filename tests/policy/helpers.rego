# Shared helpers for the cluster manifest policy tests. conftest evaluates
# every rendered document as `input` and reports every `deny` message.
# The rules implement the M5 security baseline from PLAN.md; the deliberately
# non-compliant fixture in fixtures/ proves each rule rejects before merge.
package main

import rego.v1

workload_kinds := {"Pod", "Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob"}

# Namespaces rendered from upstream bootstrap manifests that this repository
# does not author container specifications for. Flux controllers are tag-pinned
# by the committed gotk-components.yaml and updated through Renovate; every
# repository-authored workload must pin image digests and bound ephemeral
# storage.
digest_exempt_namespaces := {"flux-system"}
ephemeral_storage_exempt_namespaces := {"flux-system"}

pod_spec(obj) := obj.spec if {
	obj.kind == "Pod"
}

pod_spec(obj) := obj.spec.template.spec if {
	obj.kind in {"Deployment", "StatefulSet", "DaemonSet", "Job"}
}

pod_spec(obj) := obj.spec.jobTemplate.spec.template.spec if {
	obj.kind == "CronJob"
}

all_containers(obj) := cs if {
	spec := pod_spec(obj)
	cs := array.concat(
		array.concat(object.get(spec, "containers", []), object.get(spec, "initContainers", [])),
		object.get(spec, "ephemeralContainers", []),
	)
}

workload_ref(obj) := sprintf("%s/%s in namespace %s", [
	object.get(obj, "kind", "?"),
	object.get(obj.metadata, "name", "?"),
	object.get(obj.metadata, "namespace", "default"),
])
