# Restricted-profile container security contexts. Every container, including
# init and ephemeral containers, must explicitly opt out of privilege
# escalation, run as a non-root user, use RuntimeDefault seccomp, add no
# capabilities, and keep an immutable root filesystem. A workload that cannot
# comply must carry the reviewed opt-out annotation on its metadata.
package main

import rego.v1

# opt-out for containers that genuinely require a writable root filesystem
allow_writable_rootfs(obj) if {
	object.get(object.get(obj.metadata, "annotations", {}), "policy.cvp.io/allow-writable-rootfs", "false") == "true"
}

deny contains sprintf("%s: container %q must not be privileged", [workload_ref(input), c.name]) if {
	input.kind in workload_kinds
	some c in all_containers(input)
	object.get(object.get(c, "securityContext", {}), "privileged", false)
}

deny contains sprintf("%s: container %q must set allowPrivilegeEscalation: false", [workload_ref(input), c.name]) if {
	input.kind in workload_kinds
	some c in all_containers(input)
	object.get(object.get(c, "securityContext", {}), "allowPrivilegeEscalation", null) != false
}

deny contains sprintf("%s: container %q must run as non-root", [workload_ref(input), c.name]) if {
	input.kind in workload_kinds
	some c in all_containers(input)
	not object.get(object.get(pod_spec(input), "securityContext", {}), "runAsNonRoot", false)
	not object.get(object.get(c, "securityContext", {}), "runAsNonRoot", false)
}

deny contains sprintf("%s: container %q must not request uid 0", [workload_ref(input), c.name]) if {
	input.kind in workload_kinds
	some c in all_containers(input)
	object.get(object.get(c, "securityContext", {}), "runAsUser", -1) == 0
}

deny contains sprintf("%s: pod %q must not request uid 0", [workload_ref(input), input.metadata.name]) if {
	input.kind in workload_kinds
	object.get(object.get(pod_spec(input), "securityContext", {}), "runAsUser", -1) == 0
}

deny contains sprintf("%s: container %q must use seccompProfile RuntimeDefault", [workload_ref(input), c.name]) if {
	input.kind in workload_kinds
	some c in all_containers(input)
	object.get(object.get(object.get(pod_spec(input), "securityContext", {}), "seccompProfile", {}), "type", "") != "RuntimeDefault"
	object.get(object.get(object.get(c, "securityContext", {}), "seccompProfile", {}), "type", "") != "RuntimeDefault"
}

deny contains sprintf("%s: container %q must not add capabilities", [workload_ref(input), c.name]) if {
	input.kind in workload_kinds
	some c in all_containers(input)
	count(object.get(object.get(object.get(c, "securityContext", {}), "capabilities", {}), "add", [])) > 0
}

deny contains sprintf("%s: container %q must set readOnlyRootFilesystem: true", [workload_ref(input), c.name]) if {
	input.kind in workload_kinds
	not allow_writable_rootfs(input)
	some c in all_containers(input)
	object.get(object.get(c, "securityContext", {}), "readOnlyRootFilesystem", false) != true
}
