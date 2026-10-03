# Unbounded workloads are rejected: every container must request and limit
# cpu and memory, and must bound ephemeral storage outside the bootstrap
# namespace (see helpers.rego for the exemption rationale).
package main

import rego.v1

missing_keys(res, section, keys) := missing if {
	values := object.get(res, section, {})
	missing := {key | some key in keys; object.get(values, key, "") == ""}
}

deny contains sprintf("%s: container %q must set requests for %s", [
	workload_ref(input), c.name, concat(", ", sort(missing)),
]) if {
	input.kind in workload_kinds
	some c in all_containers(input)
	missing := missing_keys(object.get(c, "resources", {}), "requests", ["cpu", "memory"])
	count(missing) > 0
}

deny contains sprintf("%s: container %q must set limits for %s", [
	workload_ref(input), c.name, concat(", ", sort(missing)),
]) if {
	input.kind in workload_kinds
	some c in all_containers(input)
	missing := missing_keys(object.get(c, "resources", {}), "limits", ["cpu", "memory"])
	count(missing) > 0
}

deny contains sprintf("%s: container %q must bound ephemeral storage (requests and limits)", [
	workload_ref(input), c.name,
]) if {
	input.kind in workload_kinds
	not object.get(input.metadata, "namespace", "") in ephemeral_storage_exempt_namespaces
	some c in all_containers(input)
	missing := missing_keys(object.get(c, "resources", {}), "requests", ["ephemeral-storage"])
	count(missing) > 0
}

deny contains sprintf("%s: container %q must bound ephemeral storage (requests and limits)", [
	workload_ref(input), c.name,
]) if {
	input.kind in workload_kinds
	not object.get(input.metadata, "namespace", "") in ephemeral_storage_exempt_namespaces
	some c in all_containers(input)
	missing := missing_keys(object.get(c, "resources", {}), "limits", ["ephemeral-storage"])
	count(missing) > 0
}
