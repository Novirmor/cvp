# Unbounded workloads are rejected: every container must request and limit
# cpu and memory, and must bound ephemeral storage except for pinned vendored
# controller containers.
package main

import rego.v1

missing_keys(res, section, keys) := missing if {
	values := object_field(res, section)
	missing := {key | some key in keys; not positive_quantity(object.get(values, key, ""))}
}

positive_quantity(value) if {
	is_number(value)
	value > 0
}

positive_quantity(value) if {
	is_string(value)
	parts := regex.find_all_string_submatch_n(`^\+?([0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][+-]?[0-9]+|[numkKMGTPE]|[KMGTPE]i)?$`, value, 1)
	to_number(parts[0][1]) > 0
}

deny contains sprintf("%s: container %q must set requests for %s", [workload_ref(input), c.name, concat(", ", sort(missing))]) if {
	input.kind in workload_kinds
	some c in all_containers(input)
	missing := missing_keys(object.get(c, "resources", {}), "requests", ["cpu", "memory"])
	count(missing) > 0
}

deny contains sprintf("%s: container %q must set limits for %s", [workload_ref(input), c.name, concat(", ", sort(missing))]) if {
	input.kind in workload_kinds
	some c in all_containers(input)
	missing := missing_keys(object.get(c, "resources", {}), "limits", ["cpu", "memory"])
	count(missing) > 0
}

deny contains sprintf("%s: container %q must bound ephemeral storage (requests and limits)", [workload_ref(input), c.name]) if {
	input.kind in workload_kinds
	some c in all_containers(input)
	not vendored_flux_container(input, c)
	missing := missing_keys(object.get(c, "resources", {}), "requests", ["ephemeral-storage"])
	count(missing) > 0
}

deny contains sprintf("%s: container %q must bound ephemeral storage (requests and limits)", [workload_ref(input), c.name]) if {
	input.kind in workload_kinds
	some c in all_containers(input)
	not vendored_flux_container(input, c)
	missing := missing_keys(object.get(c, "resources", {}), "limits", ["ephemeral-storage"])
	count(missing) > 0
}
