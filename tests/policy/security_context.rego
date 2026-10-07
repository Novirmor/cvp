# Restricted-profile container security contexts. Every container, including
# init and ephemeral containers, must explicitly opt out of privilege
# escalation, run as a non-root user, use RuntimeDefault seccomp, add no
# capabilities, and keep an immutable root filesystem unless the reviewed
# writable-rootfs opt-out annotation is present.
package main

import rego.v1

# opt-out for containers that genuinely require a writable root filesystem
allow_writable_rootfs(obj) if {
	object.get(object_field(object_field(obj, "metadata"), "annotations"), "policy.cvp.novirmor.io/allow-writable-rootfs", "false") == "true"
}

deny contains sprintf("%s: container %q must not be privileged", [workload_ref(input), c.name]) if {
	input.kind in workload_kinds
	some c in all_containers(input)
	object.get(object_field(c, "securityContext"), "privileged", false)
}

deny contains sprintf("%s: container %q must set allowPrivilegeEscalation: false", [workload_ref(input), c.name]) if {
	input.kind in workload_kinds
	some c in all_containers(input)
	object.get(object_field(c, "securityContext"), "allowPrivilegeEscalation", null) != false
}

deny contains sprintf("%s: container %q must run as non-root", [workload_ref(input), c.name]) if {
	input.kind in workload_kinds
	some c in all_containers(input)
	effective_security(input, c, "runAsNonRoot", false) != true
}

deny contains sprintf("%s: container %q must not request uid 0", [workload_ref(input), c.name]) if {
	input.kind in workload_kinds
	some c in all_containers(input)
	effective_security(input, c, "runAsUser", -1) == 0
}

deny contains sprintf("%s: container %q must use seccompProfile RuntimeDefault", [workload_ref(input), c.name]) if {
	input.kind in workload_kinds
	some c in all_containers(input)
	object.get(as_object(effective_security(input, c, "seccompProfile", {})), "type", "") != "RuntimeDefault"
}

deny contains sprintf("%s: container %q capabilities must drop ALL", [workload_ref(input), c.name]) if {
	input.kind in workload_kinds
	some c in all_containers(input)
	not "ALL" in array_field(object_field(object_field(c, "securityContext"), "capabilities"), "drop")
}

deny contains sprintf("%s: container %q must not add capabilities", [workload_ref(input), c.name]) if {
	input.kind in workload_kinds
	some c in all_containers(input)
	count(array_field(object_field(object_field(c, "securityContext"), "capabilities"), "add")) > 0
}

deny contains sprintf("%s: container %q must set readOnlyRootFilesystem: true", [workload_ref(input), c.name]) if {
	input.kind in workload_kinds
	not allow_writable_rootfs(input)
	some c in all_containers(input)
	object.get(object_field(c, "securityContext"), "readOnlyRootFilesystem", false) != true
}
