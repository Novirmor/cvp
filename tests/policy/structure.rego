package main

import rego.v1

deny contains sprintf("%s: workload metadata must be a map", [workload_ref(input)]) if {
	input.kind in workload_kinds
	not is_object(object.get(input, "metadata", null))
}

deny contains sprintf("%s: containers must be a nonempty array", [workload_ref(input)]) if {
	input.kind in workload_kinds
	count(array_field(pod_spec(input), "containers")) == 0
}

deny contains sprintf("%s: %s must be an array or null", [workload_ref(input), field]) if {
	input.kind in workload_kinds
	some field in {"containers", "initContainers", "ephemeralContainers", "volumes"}
	value := object.get(pod_spec(input), field, null)
	value != null
	not is_array(value)
}

deny contains sprintf("%s: container must be an object with a nonempty name", [workload_ref(input)]) if {
	input.kind in workload_kinds
	some c in all_containers(input)
	name := object.get(as_object(c), "name", "")
	not valid_container_name(name)
}

valid_container_name(name) if {
	is_string(name)
	count(name) > 0
}

security_contexts contains context if {
	input.kind in workload_kinds
	context := object.get(pod_spec(input), "securityContext", null)
}

security_contexts contains context if {
	input.kind in workload_kinds
	some c in all_containers(input)
	context := object.get(as_object(c), "securityContext", null)
}

optional_maps contains value if {
	some value in security_contexts
}

optional_maps contains value if {
	some context in security_contexts
	some key in {"seccompProfile", "capabilities"}
	value := object.get(as_object(context), key, null)
}

optional_maps contains value if {
	input.kind in workload_kinds
	some c in all_containers(input)
	value := object.get(as_object(c), "resources", null)
}

optional_maps contains value if {
	input.kind in workload_kinds
	some c in all_containers(input)
	some key in {"requests", "limits"}
	value := object.get(object_field(c, "resources"), key, null)
}

deny contains sprintf("%s: security and resource fields must be maps or null", [workload_ref(input)]) if {
	some value in optional_maps
	value != null
	not is_object(value)
}

deny contains sprintf("%s: capability lists must be arrays or null", [workload_ref(input)]) if {
	some context in security_contexts
	some key in {"add", "drop"}
	value := object.get(object_field(context, "capabilities"), key, null)
	value != null
	not is_array(value)
}
