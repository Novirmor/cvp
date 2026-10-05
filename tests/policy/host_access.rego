# Prohibited host access: host network namespaces and hostPath volumes are
# never allowed in Git-managed workloads, including the bootstrap namespace.
package main

import rego.v1

deny contains sprintf("%s: hostNetwork is forbidden", [workload_ref(input)]) if {
	input.kind in workload_kinds
	object.get(pod_spec(input), "hostNetwork", false)
}

deny contains sprintf("%s: hostIPC is forbidden", [workload_ref(input)]) if {
	input.kind in workload_kinds
	object.get(pod_spec(input), "hostIPC", false)
}

deny contains sprintf("%s: hostPID is forbidden", [workload_ref(input)]) if {
	input.kind in workload_kinds
	object.get(pod_spec(input), "hostPID", false)
}

deny contains sprintf("%s: hostPath volume %q is forbidden", [workload_ref(input), v.name]) if {
	input.kind in workload_kinds
	some v in object.get(pod_spec(input), "volumes", [])
	"hostPath" in object.keys(v)
}

deny contains sprintf("%s: container %q hostPort is forbidden", [workload_ref(input), c.name]) if {
	input.kind in workload_kinds
	some c in all_containers(input)
	some port in object.get(c, "ports", [])
	object.get(port, "hostPort", 0) != 0
}
